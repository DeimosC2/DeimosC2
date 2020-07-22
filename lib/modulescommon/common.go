package modulescommon

//ModuleCom -> Data that needs to be sent back to the server side of a module should be structured as so
type ModuleCom struct {
	AgentKey   string //Holds the name of the agent
	Server     bool   //Does the data have a corresponding server portion?
	Download   bool   //Getting the module
	Kill       bool   //Used if the module is finished
	ModuleName string //Name of the module
	ModuleType string //Type of module
	FileType   string //Platform it will run on
	Data       []byte //Data
}

//ModOutput is a simple struct for what output modules should send back
type ModOutput struct {
	AgentKey   string //Holds the name of the agent
	ModuleName string //Name of the module
	OutputType string //Type out output like Link
	Output     []byte //Output
}
