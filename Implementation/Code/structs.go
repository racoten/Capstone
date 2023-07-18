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
	ImplantUser string `json:"ImplantUser"`
	Operator    string `json:"Operator"`
	TimeToExec  string `json:"timeToExec"`
	Delay       string `json:"delay"`
	File        string `json:"File"`
	Command     string `json:"Command"`
}

type Output struct {
	ImplantID    string `json:"ImplantId"`
	Operator     string `json:"OperatorId"`
	Output       string `json:"Output"`
	DateFromLast string `json:"DateFromLast"`
}
