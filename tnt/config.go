package tnt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

var (
	ReadTimeout time.Duration
)

type Config struct {
	LocalAddr    string `json:"local"`
	ServerAddr   string `json:"server"`
	Password     string `json:"password"`
	Method       string `json:"method"`
	Timeout      int    `json:"timeout"`
	TargetDomain string `json:"target_domain"`
	TargetPort   uint16 `json:"target_port"`
}

func (c *Config) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("\nLocalAddr: %s\n", c.LocalAddr))
	buf.WriteString(fmt.Sprintf("ServerAddr: %s\n", c.ServerAddr))
	buf.WriteString(fmt.Sprintf("Password: %s\n", c.Password))
	buf.WriteString(fmt.Sprintf("Method: %s\n", c.Method))
	buf.WriteString(fmt.Sprintf("Timeout: %d\n", c.Timeout))
	buf.WriteString(fmt.Sprintf("TargetDomain: %s\n", c.TargetDomain))
	buf.WriteString(fmt.Sprintf("TargetPort: %d\n", c.TargetPort))
	return buf.String()
}

func ParseConfig(fpath string) (config *Config, err error) {
	file, err := os.Open(fpath)
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	ReadTimeout = time.Duration(config.Timeout) * time.Second

	return
}
