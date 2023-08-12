package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
)

type DNSHeader struct {
	ID            uint16
	Flags         uint16
	NumbQuestions uint16
	NumbAnswers   uint16
	NumAuthority  uint16
	NumAdditional uint16
}

type DNSQuestion struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

type DNSRecord struct {
	Name  []byte
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

type DNSPacket struct {
	Header      DNSHeader
	questions   []DNSQuestion
	Answers     []DNSRecord
	Authorities []DNSRecord
	Additional  []DNSRecord
}

func encodeDNSName(name string) []byte {
	var encoded []byte
	for _, part := range strings.Split(name, ".") {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, []byte(part)...)
	}
	encoded = append(encoded, 0)
	return encoded

}

var dnsTypeMap = map[string]uint16{
	"A":     1,
	"NS":    2,
	"CNAME": 5,
	"SOA":   6,
	"PTR":   12,
	"MX":    15,
	"TXT":   16,
	"AAAA":  28,
	"SRV":   33,
	"ANY":   255,
}

func headerToBytes(header DNSHeader) []byte {
	var bytes []byte
	temp := make([]byte, 2)
	binary.BigEndian.PutUint16(temp, header.ID)
	bytes = append(bytes, temp...)
	binary.BigEndian.PutUint16(temp, header.Flags)
	bytes = append(bytes, temp...)
	binary.BigEndian.PutUint16(temp, header.NumbQuestions)
	bytes = append(bytes, temp...)
	binary.BigEndian.PutUint16(temp, header.NumbAnswers)
	bytes = append(bytes, temp...)
	binary.BigEndian.PutUint16(temp, header.NumAuthority)
	bytes = append(bytes, temp...)
	binary.BigEndian.PutUint16(temp, header.NumAdditional)
	bytes = append(bytes, temp...)
	return bytes
}

func ipToString(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func questionToBytes(question DNSQuestion) []byte {
	var bytes []byte
	bytes = append(bytes, question.QName...)
	temp := make([]byte, 2)
	binary.BigEndian.PutUint16(temp, question.QType)
	bytes = append(bytes, temp...)
	binary.BigEndian.PutUint16(temp, question.QClass)
	bytes = append(bytes, temp...)
	return bytes
}

func buildQuery(domainName string, recordType string) []byte {
	name := encodeDNSName(domainName)
	id := rand.Intn(65535)

	//recursionDesired := 1 << 8
	//header := DNSHeader{uint16(id), uint16(recursionDesired), 1, 0, 0, 0} // Asking Server to resolve domain name with recursion
	header := DNSHeader{uint16(id), 0, 1, 0, 0, 0} // Asking Server to resolve domain name without recursion
	question := DNSQuestion{name, dnsTypeMap[recordType], 1}

	result := append(headerToBytes(header), questionToBytes(question)...)
	return result

}

func parseHeader(buffer []byte) DNSHeader {
	//fmt.Println("Received for parseHeader: ", buffer)
	var header DNSHeader
	header.ID = binary.BigEndian.Uint16(buffer[0:2])
	header.Flags = binary.BigEndian.Uint16(buffer[2:4])
	header.NumbQuestions = binary.BigEndian.Uint16(buffer[4:6])
	header.NumbAnswers = binary.BigEndian.Uint16(buffer[6:8])
	header.NumAuthority = binary.BigEndian.Uint16(buffer[8:10])
	header.NumAdditional = binary.BigEndian.Uint16(buffer[10:12])
	return header
}

// Simple DNS Name decoder
func decodeDNSNameSimple(buffer []byte, currentLocation int) ([]byte, int) {
	var name []byte
	var dnsEndMarker int
	i := currentLocation
	for i < len(buffer) {
		length := int(buffer[i])
		if length == 0 {
			break
		}
		name = append(name, buffer[i+1:i+1+length]...)
		name = append(name, '.')
		i += length + 1
		dnsEndMarker = i
	}

	// dnsEndMarker + 1 to account for the 0x00 at the end of the name, which is not included in the length due to break
	return name, dnsEndMarker + 1
}

func decodeQuestionData(buffer []byte, currentLocation int) (uint16, uint16) {
	var qType uint16
	var qClass uint16
	qType = binary.BigEndian.Uint16(buffer[currentLocation : currentLocation+2])
	qClass = binary.BigEndian.Uint16(buffer[currentLocation+2 : currentLocation+4])
	return qType, qClass
}

func parseQuestion(buffer []byte, currentLocation int) (DNSQuestion, int) {
	//fmt.Println("Received for parseQuestion: ", buffer)
	var question DNSQuestion
	var dnsEndMarker int
	question.QName, dnsEndMarker = decodeDNSNameSimple(buffer, currentLocation)
	question.QType, question.QClass = decodeQuestionData(buffer, dnsEndMarker)
	return question, dnsEndMarker + 4
}

func decodeDNSName(buffer []byte, location int) ([]byte, int) {
	var name []byte
	var dnsEndMarker int
	i := location
	for i < len(buffer) {
		length := int(buffer[i])
		if length == 0 {
			break
		} else if length >= 192 {
			name = append(name, decodeCompressedName(length, buffer, i)...)
			i += 2
			return name, i
		} else {
			name = append(name, buffer[i+1:i+1+length]...)
			name = append(name, '.')
		}
		i += length + 1
		dnsEndMarker = i
	}
	return name, dnsEndMarker
}

func decodeCompressedName(length int, buffer []byte, currentPosition int) []byte {
	offset := int(byte(length&0x3f) + buffer[currentPosition+1])
	result, _ := decodeDNSName(buffer, offset)
	return []byte(result)
}

func decodeRecordData(buffer []byte) (uint16, uint16, uint32, int) {
	var rType uint16
	var rClass uint16
	var rTTL uint32
	var rDataLength int
	rType = binary.BigEndian.Uint16(buffer[0:2])
	rClass = binary.BigEndian.Uint16(buffer[2:4])
	rTTL = binary.BigEndian.Uint32(buffer[4:8])
	rDataLength = int(binary.BigEndian.Uint16(buffer[8:10]))
	return rType, rClass, rTTL, rDataLength

}

func parseRecord(buffer []byte, currentLocation int) (DNSRecord, int) {
	var record DNSRecord
	var dataLength int
	var dnsEndMarker int
	record.Name, dnsEndMarker = decodeDNSName(buffer, currentLocation)
	record.Type, record.Class, record.TTL, dataLength = decodeRecordData(buffer[dnsEndMarker : dnsEndMarker+10])
	if record.Type == dnsTypeMap["NS"] {
		record.Data, _ = decodeDNSName(buffer, dnsEndMarker+10)
	} else {
		record.Data = buffer[dnsEndMarker+10 : dnsEndMarker+10+dataLength]
	}
	return record, dnsEndMarker + 10 + dataLength
}

func parseDNSPacket(buffer []byte) DNSPacket {
	currentLocation := 12 // Skip the header as header size is fixed to 12 bytes
	var questions []DNSQuestion
	var answers []DNSRecord
	var authorities []DNSRecord
	var additionals []DNSRecord

	header := parseHeader(buffer[0:12])

	for i := 0; i < int(header.NumbQuestions); i++ {
		var question DNSQuestion
		question, currentLocation = parseQuestion(buffer, currentLocation)
		questions = append(questions, question)
		//currentLocation += length
	}

	for i := 0; i < int(header.NumbAnswers); i++ {
		answer, length := parseRecord(buffer, currentLocation)
		answers = append(answers, answer)
		currentLocation += length + 1
	}

	for i := 0; i < int(header.NumAuthority); i++ {
		var authority DNSRecord
		authority, currentLocation = parseRecord(buffer, currentLocation)
		authorities = append(authorities, authority)
		//currentLocation += length
	}

	for i := 0; i < int(header.NumAdditional); i++ {
		var additional DNSRecord
		additional, currentLocation = parseRecord(buffer, currentLocation)
		additionals = append(additionals, additional)
		//currentLocation += length
	}

	return DNSPacket{header, questions, answers, authorities, additionals}

}

// func lookupDomain(domain string) (string, error) {
// 	query := buildQuery(domain, "A")
// 	conn, err := net.Dial("udp", "8.8.8.8:53")
// 	if err != nil {
// 		fmt.Println(err)
// 		return "", err
// 	}
// 	defer conn.Close()

// 	_, err = conn.Write(query)
// 	if err != nil {
// 		fmt.Println(err)
// 		return "", err
// 	}

// 	buffer := make([]byte, 1024)

// 	_, err = conn.Read(buffer)
// 	if err != nil {
// 		fmt.Println(err)
// 		return "", err
// 	}
// 	dnsPacket := parseDNSPacket(buffer)
// 	return ipToString(dnsPacket.Answers[0].Data), nil

// }

func sendQuery(ipAddress string, domain string, recordType string) (DNSPacket, error) {
	query := buildQuery(domain, recordType)
	conn, err := net.Dial("udp", ipAddress+":53")
	if err != nil {
		fmt.Println(err)
		return DNSPacket{}, err
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		fmt.Println(err)
		return DNSPacket{}, err
	}

	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return DNSPacket{}, err
	}

	dnsPacket := parseDNSPacket(buffer)
	return dnsPacket, nil

}

func getAnswer(dnsPacket DNSPacket) string {
	for i := range dnsPacket.Answers {
		if dnsPacket.Answers[i].Type == dnsTypeMap["A"] {
			return ipToString(dnsPacket.Answers[i].Data)
		}
	}
	return ""
}

func getNameServerIP(dnsPacket DNSPacket) string {
	for i := range dnsPacket.Additional {
		if dnsPacket.Additional[i].Type == dnsTypeMap["A"] {
			return ipToString(dnsPacket.Additional[i].Data)
		}
	}
	return ""
}

func getNameServer(dnsPacket DNSPacket) string {
	for i := range dnsPacket.Authorities {
		if dnsPacket.Authorities[i].Type == dnsTypeMap["NS"] {
			return string(dnsPacket.Authorities[i].Data)
		}
	}
	return ""
}

func resolve(domainName string, recordType string) (string, error) {
	nameServer := "198.41.0.4"
	for {
		fmt.Printf("Querying %s for %s\n", nameServer, domainName)
		dnsPacket, err := sendQuery(nameServer, domainName, recordType)
		if err != nil {
			fmt.Println(err)
			return "", err
		}
		if ip := getAnswer(dnsPacket); ip != "" {
			return ip, nil
		} else if nameServerIP := getNameServerIP(dnsPacket); nameServerIP != "" {
			nameServer = nameServerIP
		} else if nameServerDomain := getNameServer(dnsPacket); nameServerDomain != "" {
			nameServerDomain = strings.TrimSuffix(nameServerDomain, ".")
			nameServer, _ = resolve(nameServerDomain, "A")
		} else {
			return "", errors.New("no answer found")
		}
	}
}

func main() {
	result, err := resolve("twitter.com", "A")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
