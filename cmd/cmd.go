package cmd

import (
	"log"
	"os"
	"packetclt/collect"

	"github.com/urfave/cli/v2"
)

func Run() {
	App := cli.NewApp()
	App.Name = "packetclt"
	App.Version = "1.0"
	App.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "i",
			Usage:    "网卡名",
			Required: true,
		},
	}
	App.Action = func(c *cli.Context) error {
		eth := c.String("i")
		if eth != "" {
			collect.Collect(eth)
		}
		return nil
	}
	err := App.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
