package cmd

import (
	b64 "encoding/base64"
	"fmt"
	"strings"

	"github.com/OnlyF0uR/Intrusor/src/utils"
	"github.com/spf13/cobra"
)

var decodeBase64 bool

func init() {
	rootCmd.AddCommand(base64Cmd)

	base64Cmd.Flags().BoolVarP(&decodeBase64, "decode", "d", false, "Decode base64.")
}

var base64Cmd = &cobra.Command{
	Use:   "base64 [DATA]",
	Short: "Convert data to/from base64",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No arguments were provided." + utils.Reset)
			return
		}

		input := strings.Join(args, " ")

		if decodeBase64 {
			sDec, ex := b64.StdEncoding.DecodeString(input)
			if ex != nil {
				fmt.Println(utils.Red + "Could not decode the entered string." + utils.Reset)
				return
			}

			fmt.Println(utils.Green + "Output: " + utils.White + string(sDec) + utils.Reset)
		} else {
			sEnc := b64.StdEncoding.EncodeToString([]byte(input))
			fmt.Println(utils.Green + "Output: " + utils.White + sEnc + utils.Reset)
		}
	},
}
