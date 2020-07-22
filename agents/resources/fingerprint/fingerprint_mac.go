// +build darwin

package fingerprint

import (
	"encoding/xml"
	"os"
)

//FingerPrint will get the version of the Operating System
func FingerPrint() (string, string, []string) {
	var av []string
	result := map[string]interface{}{}
	av = append(av, "null")

	pListFile, err := os.Open("/System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		//logging.Logger.Println(err)
	}
	defer pListFile.Close()
	decoder := xml.NewDecoder(pListFile)
	var workingKey string
	for {
		token, _ := decoder.Token()
		if token == nil {
			break
		}
		switch start := token.(type) {
		case xml.StartElement:
			switch start.Name.Local {
			case "key":
				var k string
				err := decoder.DecodeElement(&k, &start)
				if err != nil {
					//logging.Logger.Println(err.Error())
				}
				workingKey = k
			case "string":
				var s string
				err := decoder.DecodeElement(&s, &start)
				if err != nil {
					//logging.Logger.Println(err.Error())
				}
				result[workingKey] = s
				workingKey = ""
			}
		}

	}
	return result["ProductName"].(string), result["ProductVersion"].(string), av
}
