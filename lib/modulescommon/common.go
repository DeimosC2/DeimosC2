package modulescommon

//ModuleCom -> Data that needs to be sent back to the server side of a module should be structured as so
type ModuleCom struct {
	AgentKey   string `json:"agentkey"`   //Holds the name of the agent
	Server     bool   `json:"server"`     //Does the data have a corresponding server portion?
	Download   bool   `json:"download"`   //Getting the module
	Kill       bool   `json:"kill"`       //Used if the module is finished
	ModuleName string `json:"modulename"` //Name of the module
	ModuleType string `json:"moduletype"` //Type of module
	FileType   string `json:"filetype"`   //Platform it will run on
	Data       []byte `json:"data"`       //Data
}

//ModOutput is a simple struct for what output modules should send back
type ModOutput struct {
	AgentKey   string `json:"agentkey"`   //Holds the name of the agent
	ModuleName string `json:"modulename"` //Name of the module
	OutputType string `json:"outputtype"` //Type out output like Link
	Output     []byte `json:"output"`     //Output
}
