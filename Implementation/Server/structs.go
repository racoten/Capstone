package main

type Implant struct {
	Implant string `json:"implant"`
	Modules string `json:"modules"`
	Loader  string `json:"loader"`
	CLoader string `json:"cloader"`
	Donut   string `json:"donut"`
}

type Scripts struct {
	CryptoCutter string `json:"cryptocutter"`
	Cleaner      string `json:"cleaner"`
	JunkInjector string `json:"junk_injector"`
	VagrantSSH   string `json:"vagrantssh"`
}

type Server struct {
	IP      string `json:"ip"`
	Port    string `json:"port"`
	SQLUser string `json:"sqluser"`
	SQLPass string `json:"sqlpass"`
}

type Configuration struct {
	Implant    []Implant `json:"Implant"`
	Scripts    []Scripts `json:"Scripts"`
	Server     []Server  `json:"Server"`
	BasedirWin string    `json:"basedirwin"`
	BasedirLin string    `json:"basedirlin"`
}

type Agent struct {
	Code string `json:"Code"`
}

type OperatorRegister struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phoneNumber"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Command struct {
	Input       string `json:"Input"`
	Command     string `json:"Command"`
	Args        string `json:"Args"`
	ImplantUser string `json:"ImplantUser"`
	Operator    string `json:"Operator"`
	Delay       string `json:"delay"`
	TimeToExec  string `json:"timeToExec"`
	File        string `json:"File"`
	UseSmb      string `json:"usesmb"`
	ActSmb      string `json:"actsmb"`
}

type Output struct {
	ImplantID    string `json:"ImplantId"`
	Operator     string `json:"OperatorId"`
	Output       string `json:"Output"`
	DateFromLast string `json:"DateFromLast"`
}

type Listener struct {
	Name   string `json:"Name"`
	IP     string `json:"IP"`
	Port   string `json:"Port"`
	Header string `json:"Header"`
}

type Message struct {
	Username string `json:"username"`
	Message  string `json:"message"`
}

type ListenerWrapper struct {
	Listeners []Listener `json:"Listeners"`
}

type Device struct {
	ID              string `json:"ID"`
	DeviceName      string `json:"DeviceName"`
	Username        string `json:"Username"`
	OperatorID      int    `json:"OperatorID"`
	CPUArchitecture string `json:"CPUArchitecture"`
	GPUInfo         string `json:"GPUInfo"`
	RAMInfo         int    `json:"RAMInfo"`
	OSName          string `json:"OSName"`
	NetworkInfo     string `json:"NetworkInfo"`
	CurrentDate     string `json:"CurrentDate"`
}

type ImplantConfig struct {
	Name   string `json:"Name"`
	IP     string `json:"IP"`
	Port   string `json:"Port"`
	Header string `json:"Header"`
}

type Alerts struct {
	Alert string `json:"alert"`
}

type Token struct {
	ImplantToken string `json:"token"`
}
