package com.chadwickboggs.ntrutil;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import net.sf.ntru.encrypt.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.*;


public class NtrUtil {

    private static final String USAGE_MESSAGE = "\n"
            + "\t$ ntrutil [options] [<-e|--encrypt> [input filename]] [<-d|--decrypt> [input filename]] "
            + "[<-o|--output> <output filename>]\n\n"
            + "\t\tEncrypts or decrypts stdin or an input file using the NTRU algorithm.  The output is written"
            + " either to stdout or an output file.\n\n"
            + "\tOptions:\n\n"
            + "\t\t[-e|--encrypt]\t\t\tEncrypt stdin or an input file.\n"
            + "\t\t[-d|--decrypt]\t\t\tDecrypt stdin or an input file.\n"
            + "\t\t[-o|--output]\t\t\tThe name of the file into which the output shall be written.\n"
            + "\t\t[-bi|--base64input]\t\tThe input is Base64 encoded.\n"
            + "\t\t[-bo|--base64output]\t\tEncode the output with Base64 encoding.\n"
            + "\t\t[-v|--verbose]\t\t\tVerbose display processing information.\n"
            + "\t\t[-?|-h|-u|--help|--usage]\tDisplay usage information.\n";

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.ntrutil";
    private static final String PRIVATE_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_private_key";
    private static final String PUBLIC_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_public_key";
    private static final String ENCRYPTION_PARAMETERS_FILENAME = USER_STORE_FOLDER + "/encryption_parameters";

    private static NtruEncrypt ntru = null;
    private static EncryptionParameters encryptionParameters = null;
    private static EncryptionKeyPair kp = null;


    public static void main( @Nullable String... args ) throws IOException {
        if ( args == null || args.length == 0 ) {
            System.out.println( USAGE_MESSAGE );

            System.exit( 0 );
        }

        final OptionParser parser = new OptionParser( "e?:?d?:?o:v?h?u??" );
        parser.recognizeAlternativeLongOptions( true );
        parser.accepts( "encrypt" );
        parser.accepts( "decrypt" );
        parser.accepts( "output" );
        parser.accepts( "bi" );
        parser.accepts( "base64input" );
        parser.accepts( "bo" );
        parser.accepts( "base64output" );
        parser.accepts( "verbose" );
        parser.accepts( "help" );
        parser.accepts( "usage" );

        try {
            final OptionSet options = parser.parse( args );

            if ( options.has( "?" ) || options.has( "h" ) || options.has( "u" )
                    || options.has( "help" ) || options.has( "usage" ) ) {
                System.out.println( USAGE_MESSAGE );

                System.exit( 0 );
            }

            byte[] input;
            byte[] output = new byte[0];

            if ( options.has( "e" ) || options.has( "encrypt" ) ) {

                if ( options.hasArgument( "e" ) || options.hasArgument( "encrypt" ) ) {
                    final String filename = ( String ) (options.hasArgument( "e" ) ? options.valueOf( "e" )
                            : options.valueOf( "encrypt" ));

                    input = input( filename );
                } else {
                    input = input();
                }

                if ( options.has( "bi" ) || options.has( "base64input" ) ) {
                    input = Base64.decode( input );
                }

                output = encrypt( input );
            } else if ( options.has( "d" ) || options.has( "decrypt" ) ) {

                if ( options.hasArgument( "d" ) || options.hasArgument( "decrypt" ) ) {
                    final String filename = ( String ) (options.hasArgument( "d" ) ? options.valueOf( "d" )
                            : options.valueOf( "decrypt" ));

                    input = input( filename );
                } else {
                    input = input();
                }

                if ( options.has( "bi" ) || options.has( "base64input" ) ) {
                    input = Base64.decode( input );
                }

                output = decrypt( input );
            }

            if ( options.has( "bo" ) || options.has( "base64output" ) ) {
                output = Base64.encode( output ).getBytes();
            }

            if ( !options.has( "o" ) && !options.has( "output" ) ) {
                System.out.println( new String( output ) );
            } else {
                final String filename = ( String ) (options.hasArgument( "o" ) ? options.valueOf( "o" )
                        : options.valueOf( "output" ));

                output( output, filename );
            }
        } catch ( Throwable t ) {
            System.err.println( t.getMessage() );

            System.exit( 1 );
        }

        System.exit( 0 );
    }


    @NotNull
    private static byte[] input() throws IOException {
        return input( System.in );
    }


    @NotNull
    private static byte[] input( @NotNull final String filename ) throws IOException {
        final FileInputStream inputStream = new FileInputStream( filename );

        return input( inputStream );
    }


    @NotNull
    private static byte[] input( @NotNull final InputStream inputStream ) throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] value = new byte[1];
        int numRead;
        while ( (numRead = inputStream.read( value )) >= 0 ) {
            if ( numRead > 0 ) {
                outputStream.write( value );
            }
        }

        return outputStream.toByteArray();
    }


    private static void output( @NotNull byte[] bytes, @NotNull final String filename ) throws IOException {
        final FileOutputStream outputStream = new FileOutputStream( filename );
        outputStream.write( bytes );
        outputStream.close();
    }


    @NotNull
    private static byte[] encrypt( @NotNull final byte[] message ) throws IOException {
        byte[] enc = getNTRU().encrypt( message, getKeyPair().getPublic() );

        return enc;
    }

    @NotNull
    private static byte[] decrypt( @NotNull final byte[] message ) throws IOException {
        byte[] dec = getNTRU().decrypt( message, getKeyPair() );

        return dec;
    }

    @NotNull
    private static NtruEncrypt getNTRU() throws IOException {
        if ( ntru == null ) {
            loadNTRU();
        }

        return ntru;
    }

    @NotNull
    private static EncryptionKeyPair getKeyPair() throws IOException {
        if ( kp == null ) {
            loadKeyPair();
        }

        return kp;
    }


    private static EncryptionParameters getEncryptionParameters() throws IOException {
        if ( encryptionParameters == null ) {
            loadEncryptionParameters();
        }

        return encryptionParameters;
    }

    private static void loadEncryptionParameters() throws IOException {
        File file = new File( ENCRYPTION_PARAMETERS_FILENAME );

        if ( file.isFile() && file.canRead() ) {
            FileInputStream inputStream = new FileInputStream( file );
            encryptionParameters = new EncryptionParameters( inputStream );
        }
        else {
            encryptionParameters = EncryptionParameters.APR2011_439_FAST;

            new File( USER_STORE_FOLDER ).mkdirs();

            final FileOutputStream outputStream = new FileOutputStream( ENCRYPTION_PARAMETERS_FILENAME );
            encryptionParameters.writeTo( outputStream );
        }
    }

    private static void loadNTRU() throws IOException {
        EncryptionParameters encryptionParameters = getEncryptionParameters();
        ntru = new NtruEncrypt( encryptionParameters );
    }

    private static void loadKeyPair() throws IOException {
        File privateKeyFile = new File( PRIVATE_KEY_FILENAME );
        File publicKeyFile = new File( PUBLIC_KEY_FILENAME );

        if ( privateKeyFile.isFile() && privateKeyFile.canRead()
                && publicKeyFile.isFile() && publicKeyFile.canRead() ) {
            FileInputStream inputStream = new FileInputStream( privateKeyFile );
            EncryptionPrivateKey privateKey = new EncryptionPrivateKey( inputStream, encryptionParameters );

            inputStream = new FileInputStream( publicKeyFile );
            EncryptionPublicKey publicKey = new EncryptionPublicKey( inputStream, encryptionParameters );

            kp = new EncryptionKeyPair(privateKey, publicKey);
        }
        else {
            kp = getNTRU().generateKeyPair();

            new File( USER_STORE_FOLDER ).mkdirs();

            FileOutputStream outputStream = new FileOutputStream( PRIVATE_KEY_FILENAME );
            kp.getPrivate().writeTo( outputStream );

            outputStream = new FileOutputStream( PUBLIC_KEY_FILENAME );
            kp.getPublic().writeTo( outputStream );
        }
    }

}