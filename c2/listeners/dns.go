package listeners

/*
Code is a modified version of Sensepost's godoh found at the below link:
https://github.com/sensepost/goDoH
*/

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"

	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/agents"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/validation"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/crypto"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/utils"
	"github.com/miekg/dns"
)

const (

	// Request stream status
	streamStart     = 0xbe
	streamData      = 0xef
	streamEnd       = 0xca
	fileProtocol    = iota
	initProtocol    = 1
	checkinProtocol = 2
	moduleProtocol  = 6
)

// TXT record default responses
var (
	noCmdTxtResponse = []string{
		"v=B2B3FE1C",
	}
	errorTxtResponse = []string{
		"v=D31CFAA4",
	}
	cmdTxtResponse = []string{
		"v=A9F466E8",
	}
	firsttime           = "getname"
	checkin             = "checkin"
	successDNSResponse  = "1.1.1.1"
	failureDNSResponse  = "1.1.1.2"
	jobExistDNSResponse = "8.8.8.8"
)

var streamSpool = map[string]DNSBuffer{}

/*
going to build support in for google, cloudflare and raw for now
*/

// DNSBuffer represents a pending DNS conversation
type DNSBuffer struct {
	Identifier string
	Data       []byte
	Seq        int
	Started    bool
	Finished   bool
	Protocol   int
}

//StartDNSHTTPSServer is used to start the DNS over https server
//List options is pretty different for this one so that needs to be evaluated
func StartDNSHTTPSServer(newListener ListOptions, aesKey []byte) (bool, *dns.Server) {
	logging.Logger.Println("Starting DNS Server")
	m := newListener.Advanced.(map[string]interface{})
	if !validation.ValidateMap(m, []string{"firsttime", "checkin", "successResponse", "failureResponse", "jobExists"}) {
		return false, nil
	}
	//Set the values
	firsttime = m["firsttime"].(string)
	checkin = m["checkin"].(string)
	successDNSResponse = m["successResponse"].(string)
	failureDNSResponse = m["failureResponse"].(string)
	jobExistDNSResponse = m["jobExists"].(string)

	//first i need to start the server up we will only allow one
	//Doing it all here so ther variables are able to be access by the handle function
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		logging.Logger.Println("Function Called")
		msg := dns.Msg{}
		msg.SetReply(r)

		// Setup the response we will send. By default we assume everything
		// will be successful and flip to failure as needed.
		msg.Authoritative = true
		domain := msg.Question[0].Name
		logging.Logger.Println("Domain is:", domain)
		aRecordResponse := successDNSResponse
		txtRecordResponse := noCmdTxtResponse

		// Now, depending on the question we got, parse, split and do what is needed.
		logging.Logger.Println("The Question is: ", r.Question[0])
		switch r.Question[0].Qtype {
		case dns.TypeA:
			ident, streamType, seq, transferProtocol, byteData, err := parseARRLabels(r)
			if err != nil {
				aRecordResponse = err.Error()
				break
			}

			//now that the data is coming in i need to combine it?
			// A few things can happen here. Many of the code paths rely on
			// knowing whether we have an existing stream for this ident. So
			// get the status of that and save the DNSSteam if we have it.
			bufferRecord, ok := streamSpool[ident]

			// Handle new streams by taking note and starting them
			if (streamType == streamStart) && !ok {

				DNSBuf := &DNSBuffer{
					Identifier: ident,
					Seq:        seq,
					Started:    true,
					Finished:   false,
					Protocol:   transferProtocol,
				}

				// Add this new stream identifier
				streamSpool[ident] = *DNSBuf
				logging.Logger.Println("New incoming DNS stream started")

				break
			}

			// Error cases for a new stream request
			if (streamType == streamStart) && ok {
				logging.Logger.Println("Tried to start a new stream for an already recorded identifier. Bailing")
				aRecordResponse = failureDNSResponse
				break
			}

			// Handle appending data to streams
			if (streamType == streamData) && ok && !bufferRecord.Finished {

				bufferRecord.Data = append(bufferRecord.Data, byteData...)
				bufferRecord.Seq = seq

				// update the buffer for this client
				streamSpool[ident] = bufferRecord

				//logging.Logger.Println("Wrote new data chunk")
				break
			}

			// Handle errors for data appends
			if (streamType == streamData) && !ok {
				logging.Logger.Println("Tried to append to a steam that is not registered. Bailing")
				aRecordResponse = failureDNSResponse
				break
			}

			if (streamType == streamData) && ok && bufferRecord.Finished {
				logging.Logger.Println("Tried to append to a steam that is already finished. Bailing")
				aRecordResponse = failureDNSResponse
				break
			}

			// Handle closing Streams
			if (streamType == streamEnd) && ok && !bufferRecord.Finished {
				bufferRecord.Finished = true
				bufferRecord.Started = false
				bufferRecord.Seq = seq

				// update the buffer for this client
				streamSpool[ident] = bufferRecord

				decMsg := utils.HandleIncomingData(bufferRecord.Data, aesKey)

				response := handleData(bufferRecord.Protocol, string(decMsg[36:]), string(decMsg[0:36]), newListener.Key)

				aRecordResponse = response
			}

			// Handle closing errors
			if (streamType == streamEnd) && !ok {
				logging.Logger.Println("Tried to append to a steam that is not known. Bailing")
				aRecordResponse = failureDNSResponse
				break
			}

			break

		case dns.TypeTXT:
			ident, err := parseTxtRRLabels(r)
			if err != nil {
				logging.Logger.Println("Failed to parse identifer: ", err)
				txtRecordResponse = errorTxtResponse
				break
			}

			switch ident {
			case firsttime:
				nName := register("", newListener.Key, true, "", "")
				encMsg := crypto.Encrypt([]byte(nName), aesKey)
				txtRecordResponse = []string{hex.EncodeToString(encMsg)}
			default:
				if len(ident) == 36 {
					j := utils.PrepData("", agents.GetJobs(ident), aesKey)
					var newResponse []string
					hexJ := hex.EncodeToString(j)

					q, r := len(hexJ)/255, len(hexJ)%255
					if r != 0 {
						q++
					}
					if q > 1 {
						for i := 0; i < q; i++ {
							x := i * 255
							if len(hexJ) < x+255 {
								y := len(hexJ) - x
								newResponse = append(newResponse, hexJ[x:(x+y)])
							} else {
								newResponse = append(newResponse, hexJ[x:(x+255)])
							}
						}

					} else {
						newResponse = []string{hexJ}
					}

					txtRecordResponse = newResponse
				}
			}
		}
		switch r.Question[0].Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(aRecordResponse),
			})
			break
		case dns.TypeTXT:
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
				Txt: txtRecordResponse,
			})
		}
		w.WriteMsg(&msg)
	})

	dnsServer := &dns.Server{
		Addr: ":53",
		Net:  "udp",
	}

	go func() bool {
		logging.Logger.Println("Starting the DNS Server...")
		if err := dnsServer.ListenAndServe(); err != nil {
			logging.Logger.Println("Failed to set udp listener\n", err.Error())
			return false
		}
		return true
	}()

	return true, dnsServer
}

func handleData(msgType int, data string, agentKey string, listenerKey string) string {
	logging.Logger.Println("DNS Agent key is:", agentKey)
	switch msgType {
	case 1:
		register(data, listenerKey, true, agentKey, "")
		return successDNSResponse
	case 2:
		logging.Logger.Println("checkin called, data is: ", data)
		checkIn(data, agentKey, "")
		if agents.JobsExist(agentKey) {
			return jobExistDNSResponse
		}
	case 6:
		ModHandler(data)
	default:
		logging.Logger.Println("How did you get here?")
		return ""
	}
	return ""
}

// parseARRLabels splits and parses relevant labels from a question
func parseARRLabels(r *dns.Msg) (string, byte, int, int, []byte, error) {

	// A hostnames labels are what is interesting to us. Extract them.
	hsq := strings.Split(r.Question[0].String(), ".")
	logging.Logger.Println(hsq)

	if len(hsq) <= 9 {
		logging.Logger.Println("Question had less than 9 labels, bailing.")
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(failureDNSResponse)
	}

	// Based on the protocol, we have fields to parse.
	// See protocol.utils.Requestify for details.

	// the first label will have a ;. a dig thing.
	ident := strings.Split(hsq[0], ";")[1]

	streamTypeBytes, err := hex.DecodeString(hsq[1])
	if err != nil {
		logging.Logger.Println("Failed to convert stream type to bytes:", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(failureDNSResponse)
	}
	streamType := streamTypeBytes[0]

	seq, err := strconv.Atoi(hsq[2])
	if err != nil {
		logging.Logger.Println("Failed to convert sequence to Integer:", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(failureDNSResponse)
	}

	transferProtocol, err := strconv.Atoi(hsq[4])
	if err != nil {
		logging.Logger.Println("Failed to convert protocol to Integer:", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(failureDNSResponse)
	}

	// dataLen is used only in this function to determine the concat
	// amount for data itself.
	dataLen, err := strconv.Atoi(hsq[5])
	if err != nil {
		logging.Logger.Println("Failed to convert data length to Integer:", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(failureDNSResponse)
	}

	// build up the data variable. We assume of a label was 0
	// then the data is not interesting.
	var data string
	switch dataLen {
	case 1:
		data = hsq[6]
		break
	case 2:
		data = hsq[6] + hsq[7]
		break
	case 3:
		data = hsq[6] + hsq[7] + hsq[8]
		break
	}

	// decode the data
	byteData, err := hex.DecodeString(data)
	if err != nil {
		logging.Logger.Println("Could not decode data:", err)
		return "", 0x00, 0, 0, []byte{0x00}, errors.New(failureDNSResponse)
	}

	// crc32 check
	if hsq[3] != fmt.Sprintf("%02x", crc32.ChecksumIEEE(byteData)) {
		logging.Logger.Println("CRC32 Error")
	}

	return ident, streamType, seq, transferProtocol, byteData, nil
}

// parseARRLabels splits and parses relevant labels from a question
func parseTxtRRLabels(r *dns.Msg) (string, error) {

	// A hostnames labels are what is interesting to us. Extract them.
	hsq := strings.Split(r.Question[0].String(), ".")
	logging.Logger.Println("HSQ: ", hsq)

	if len(hsq) <= 1 {
		logging.Logger.Println("TXT Question had less than 1 labels, bailing.")
		return "", errors.New(failureDNSResponse)
	}

	// the first label will have a ;. a dig thing.
	identData := hsq[1]
	logging.Logger.Println(identData)
	identBytes, err := hex.DecodeString(identData)
	if err != nil {
		logging.Logger.Println("Failed to decode ident bytes:", err)
		return "", errors.New(failureDNSResponse)
	}
	ident := string(identBytes)

	//var ident2 string
	if len(hsq) == 6 {
		identData := hsq[2]
		identBytes, err := hex.DecodeString(identData)
		if err != nil {
			logging.Logger.Println("Failed to decode ident bytes:", err)
			return "", errors.New(failureDNSResponse)
		}
		ident = ident + string(identBytes)
	}
	return ident, nil
}
