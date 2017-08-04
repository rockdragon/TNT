# TNT
an experimental proxy

## client
usage:
```
go run cli/local-tnt/local.go -c cli/config-example/config.json
```


## server
usage:
```
go run cli/server-tnt/server.go -c cli/config-example/config.json
```

## configuration

#### sample:
[cli/config-example/config.json](https://github.com/rockdragon/TNT/blob/master/cli/config-example/config.json)

#### explanation of fields:
* local:  address of local socks5 server
* server: address of remote proxy server
* password: password used by both ends
* method: cipher method
* timeout: network timeout
* target_domain: domain of fake traffic (only used by local)
* target_port: port of fake traffic (only used by local)
