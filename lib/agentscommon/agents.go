package agentscommon

//JobOutput deals with agent job outputs
type JobOutput struct {
	JobName string //name of the job attempted
	Results string //job results
}

//DownloadOutput is used to hold the data for download jobs
type DownloadOutput struct {
	Filename string
	FileData string
}

//PivotOutput holds output from links further down the chain
type PivotOutput struct {
	AgentKey string
	MsgType  string
	Data     string
}
