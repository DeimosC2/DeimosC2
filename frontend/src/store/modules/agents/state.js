// type Agent struct {
//   Key      string     //Agent UUID4 Key
//   OS        string     //Agent's OS
//   Hostname  string     //Agent's hostname
//   Username  string     //Username of victim
//   LocalIP   string     //Local IP
//   AgentPath string     //Agent Path
//   Shellz    []string   //Available System Shells
//   Pid       int        //Get PID of agent
//   Jobs      []AgentJob //Holds the jobs for that agent
// }

export default {
  initialized: false,
  agents: [
    // {
    //   Key: 'c-c-c-A1',
    //   AgentPath: 'c:\\temp\\agent.exe',
    //   LocalIP: '1.1.1.1',
    //   Username: 'Bob',
    //   Hostname: 'Bob\'s-pc',
    //   date_added: '2019-01-01 00:00:00',
    //   last_seen: '2019-08-07 00:00:01',
    //   OS: 'Windows XP',
    // },
  ],
  filesToUpload: [
    // used for the file upload component
  ],
  modulesSettings: [],
  comments: {}
};
