package agentscommon

//JobOutput deals with agent job outputs
type JobOutput struct {
	JobName string `json:"jobname"` //name of the job attempted
	Results string `json:"results"` //job results
}

//DownloadOutput is used to hold the data for download jobs
type DownloadOutput struct {
	Filename string `json:"filename"`
	FileData string `json:"filedata"`
}

//PivotOutput holds output from links further down the chain
type PivotOutput struct {
	AgentKey string `json:"agentkey"`
	MsgType  string `json:"msgtype"`
	Data     string `json:"data"`
}
