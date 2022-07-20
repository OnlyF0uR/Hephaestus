package cmd

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/OnlyF0uR/Hephaestus/src/utils"
	"github.com/spf13/cobra"
)

var decodeHex bool
var enableAsciiHex bool

func init() {
	rootCmd.AddCommand(hexCmd)

	hexCmd.Flags().BoolVarP(&decodeHex, "decode", "d", false, "Convert from hex.")
	hexCmd.Flags().BoolVarP(&enableAsciiHex, "ascii", "a", false, "Enabled ASCII convertion.")
}

var hexCmd = &cobra.Command{
	Use:   "hex [DATA]",
	Short: "Convert integers and text to/from hexadecimal",
	Run: func(_ *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No arguments were provided." + utils.Reset)
			return
		}

		input := strings.Join(args, " ")

		// Check if we are decoding
		if decodeHex {
			if enableAsciiHex {
				res, ex := hex.DecodeString(input)
				if ex != nil {
					fmt.Println(utils.Red + "Invalid hex encoded ASCII text was provided." + utils.Reset)
					return
				}

				fmt.Println(utils.Green + "Output: " + utils.White + string(res) + utils.Reset)
			} else {
				res, ex := strconv.ParseInt(input, 16, 64)
				if ex != nil {
					fmt.Println(utils.Red + "Entered an invalid hex encoded integer, use -a for ASCII conversion." + utils.Reset)
					return
				}

				fmt.Println(utils.Green + "Output: " + utils.White + fmt.Sprint(res) + utils.Reset)
			}
		} else {
			// Is ascii enabled
			if enableAsciiHex {
				hex := hex.EncodeToString([]byte(input))
				fmt.Println(hex)
			} else {
				// Check if arguments is a number
				n, ex := strconv.ParseInt(input, 10, 64)
				if ex != nil {
					fmt.Println(utils.Red + "A number is required, use the -a flag to convert ASCII text." + utils.Reset)
					return
				}

				fmt.Println(utils.Green + "Output: " + utils.White + strconv.FormatInt(n, 16) + utils.Reset)
			}
		}
	},
}
