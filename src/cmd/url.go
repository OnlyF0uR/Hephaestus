package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/OnlyF0uR/Hephaestus/src/utils"
	"github.com/spf13/cobra"
)

var decodeUrl bool

func init() {
	rootCmd.AddCommand(urlCmd)

	urlCmd.Flags().BoolVarP(&decodeUrl, "decode", "d", false, "Decode url.")
}

var urlCmd = &cobra.Command{
	Use:   "url [DATA]",
	Short: "Url encoding/decoding for strings",
	Run: func(_ *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No arguments were provided." + utils.Reset)
			return
		}

		input := strings.Join(args, " ")

		if decodeUrl {
			res, ex := url.QueryUnescape(input)
			if ex != nil {
				fmt.Println(utils.Red + "Could not decode the entered string." + utils.Reset)
				return
			}

			fmt.Println(utils.Green + "Output: " + utils.White + res + utils.Reset)
		} else {
			res := url.QueryEscape(input)
			fmt.Println(utils.Green + "Output: " + utils.White + res + utils.Reset)
		}
	},
}
