package httpstechniques

import "strings"

//Non-DomainHiding Code
var (
	//Normal HTTPS agent configuration code
	mainCode string = "http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}"

	//Imports required for normal HTTPS Agent operations
	imports string = `
	"crypto/tls"
	`

	//HTTP Post code for send message function required for domain hiding
	httpPostCall string = `http.Post(("https://" + host + ":" + port + msgType), "application/json", bytes.NewBuffer(fullMessage))`
)

//StageNormalCode will dynamically create the code for the requested technique
func StageNormalCode(output string, host string, port string) string {
	//Start building the code
	output = strings.Replace(string(output), "{{DYNAMIC_IMPORTS}}", imports, -1)
	output = strings.Replace(string(output), "{{HOST}}", host, -1)
	output = strings.Replace(string(output), "{{PORT}}", port, -1)

	output = strings.Replace(string(output), "{{DYNAMIC_VARIABLES}}", "", -1)

	output = strings.Replace(string(output), "{{DYNAMIC_MAIN_CODE}}", mainCode, -1)

	output = strings.Replace(string(output), "{{DYNAMIC_HTTP_POST_CALL}}", httpPostCall, -1)

	return output
}
