// Copyright (c) 2020, SIXGEN Inc
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of SIXGEN nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Based on https://github.com/ahhh/godns (No license)
package domainhiding

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

var resolvers = []string{
	"https://dns.twnic.tw/dns-query",
	"https://doh-2.seby.io/dns-query",
	// "https://dns.containerpi.com/dns-query", // Down?
	"https://cloudflare-dns.com/dns-query",
	"https://doh-fi.blahdns.com/dns-query",
	"https://doh-jp.blahdns.com/dns-query",
	"https://doh-de.blahdns.com/dns-query",
	"https://dns.dns-over-https.com/dns-query",
	"https://doh.securedns.eu/dns-query",
	"https://dns.rubyfish.cn/dns-query",
	"https://mozilla.cloudflare-dns.com/dns-query", // Firefox uses this as default (allowed by Untangle)
	"https://trr.dns.nextdns.io/dns-query",         // Firefox has this as an option (not allowed by Untangle)
	"https://dns.google/dns-query",
	"https://dns10.quad9.net/dns-query",
	"https://doh.dns.sb/dns-query",
}

type DNSResponse struct {
	Status   int        `json:"Status"`
	TC       bool       `json:"TC"`
	RD       bool       `json:"RD"`
	AD       bool       `json:"AD"`
	CD       bool       `json:"CD"`
	Question []Question `json:"Question"`
	Answer   []Answer   `json:"Answer"`
}

type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func shuffle(src []string) []string {
	final := make([]string, len(src))
	rand.Seed(time.Now().UnixNano())
	perm := rand.Perm(len(src))

	for i, v := range perm {
		final[v] = src[i]
	}
	return final
}

// For cleaner logging
type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(string(bytes))
}

func QueryESNIKeysForHostDoH(hostname string, insecureSkipVerify bool) ([]byte, error) {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))
	myResolvers := shuffle(resolvers)
	for _, resolverTarget := range myResolvers {
		//fmt.Println("[+] Using resolver: " + resolverTarget)
		response, err := BaseRequest(resolverTarget, "_esni."+hostname, "TXT", insecureSkipVerify)
		if err != nil {
			log.Printf("[E] Error: %v", err)
			// Try the next resolver
			continue
		}
		var responseJson DNSResponse
		// log.Println(response)
		json.Unmarshal([]byte(response), &responseJson)
		if len(responseJson.Answer) == 0 {
			return nil, errors.New("got no data from DNS query")
		}
		data := trimQuotes(responseJson.Answer[0].Data)
		// log.Println(data)
		dataBytes, err := base64.StdEncoding.DecodeString(data)
		if err != nil && strings.HasPrefix(err.Error(), "illegal base64 data") {
			log.Printf("[!] Could not decode response, possible CNAME")
			return QueryESNIKeysForHostDoH("cloudflare.com", insecureSkipVerify) // All CF domains use the same key, worth a shot
		} else if err != nil {
			log.Printf("[E] Error: %v", err)

		} else {
			// log.Println(dataBytes)
			return dataBytes, nil
		}
	}
	return nil, errors.New("no resolver could be reached")
}

// BaseRequest makes a DNS over HTTP (DOH) GET request for a specified query
func BaseRequest(server, query, qtype string, insecureSkipVerify bool) (string, error) {
	//encquery := base64.StdEncoding.EncodeToString([]byte(query))
	//encquery = url.QueryEscape(encquery)
	qurl := server + "?name=" + query + "&type=" + qtype
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		TLSHandshakeTimeout: time.Second * 5,
	}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest("GET", qurl, nil)
	req.Header.Set("accept", "application/dns-json")
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[E] Error getting the url")
		return "", err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[E] Error getting the url")
		return "", err
	}
	return string(body), nil
}
