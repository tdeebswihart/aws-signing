package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/BSick7/aws-signing/cli"
	"github.com/BSick7/aws-signing/config"
	"github.com/BSick7/aws-signing/signing"
)

var (
	usage = `aws-reverse-proxy [options...]
Runs a reverse proxy signing any requests upon relay to AWS services.

Options:

 -p, --port                   Reverse proxy port to listen.
                              Default: 9200
` + cli.AwsArgs{}.Options()

	defaultPort = 9200
)

func main() {
	cfg, err := parse(os.Args)
	if err != nil {
		log.Fatalf("error parsing: %s", err)
	}

	transport, err := cfg.Aws.Transport()
	if err != nil {
		log.Fatalf("error creating transport: %s\n", err)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: signing.NewReverseProxy(cfg.Aws.EndpointUrl(), transport),
	}
	log.Printf("listening on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Println(err)
	}
}

func parse(args []string) (config.ReverseProxy, error) {
	flags := flag.NewFlagSet("aws-reverse-proxy", flag.ContinueOnError)
	flags.Usage = func() {
		log.Println(usage)
	}

	var port int
	flags.IntVar(&port, "port", 0, "reverse proxy port")
	flags.IntVar(&port, "p", 0, "reverse proxy port (shorthand)")

	var configDir string
	flags.StringVar(&configDir, "config-dir", "", "config directory")

	a := &cli.AwsArgs{}
	a.AddFlags(flags)

	if err := flags.Parse(args[1:]); err != nil {
		return config.ReverseProxy{}, err
	}

	cliaws, err := a.Config()
	if err != nil {
		return config.ReverseProxy{}, err
	}
	cl := config.ReverseProxy{
		Port: port,
		Aws:  cliaws,
	}

	result := config.MergeReverseProxy(
		config.DefaultReverseProxy,
		config.EnvReverseProxy,
		cl,
	)

	if configDir != "" {
		var dir config.ReverseProxy
		if err := config.HclUnmarshalDir(configDir, &dir); err != nil {
			return config.ReverseProxy{}, fmt.Errorf("error reading config dir %q: %s", configDir, err)
		}
		result = config.MergeReverseProxy(result, dir)
	}

	return result, nil
}
