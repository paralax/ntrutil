
$ bin/ntrutil -?

	$ ntrutil [options] [<-e|--encrypt> [input filename]] [<-d|--decrypt> [input filename]] [<-o|--output> <output filename>]

		Encrypts or decrypts stdin or an input file using the NTRU algorithm.  The output is written either to stdout or an output file.

	Options:

		[-e|--encrypt]			Encrypt stdin or an input file.
		[-d|--decrypt]			Decrypt stdin or an input file.
		[-o|--output]			The name of the file into which the output shall be written.
		[-bi|--base64input]		The input is Base64 encoded.
		[-bo|--base64output]		Encode the output with Base64 encoding.
		[-v|--verbose]			Verbose display processing information.
		[-?|-h|-u|--help|--usage]	Display usage information.

