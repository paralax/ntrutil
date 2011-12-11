package com.tagfoster.ntrutil;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import net.sf.ntru.encrypt.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.*;


public class NtrUtil {

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.ntrutil";
    private static final String PRIVATE_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_private_key";
    private static final String PUBLIC_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_public_key";
    private static final String ENCRYPTION_PARAMETERS_FILENAME = USER_STORE_FOLDER + "/encryption_parameters";
    private static final String USAGE_TXT_FILENAME = "usage.txt";

    private static final InputStream STDIN = System.in;
    private static final PrintStream STDOUT = System.out;
    private static final PrintStream STDERR = System.err;
    private static final InputStreamReader STDIN_READER = new InputStreamReader( STDIN );
    private static final int CHUNK_LENGTH = 604;

    private static NtruEncrypt ntru = null;
    private static EncryptionParameters encryptionParameters = null;
    private static EncryptionKeyPair kp = null;
    private static int maxMessageLength = 64;


    public static void main( @Nullable String... args ) throws IOException {
        if ( args == null || args.length == 0 ) {
            NtrUtil.STDOUT.println( usageMessage() );

            exit( 0 );
        }

        try {

            final OptionSet options = getCliParser().parse( args );

            if ( options.has( "?" ) || options.has( "h" ) || options.has( "u" )
                    || options.has( "help" ) || options.has( "usage" ) ) {
                NtrUtil.STDOUT.println( usageMessage() );

                exit( 0 );
            }

            String inputString = "";
            byte[] input = new byte[0];
            byte[] output = new byte[0];

            boolean didRead = false;

            while ( true ) {

                //
                // Read one chunk of input.
                //

                if ( options.has( "e" ) || options.has( "encrypt" ) ) {
                    input = input();
                } else if ( options.has( "d" ) || options.has( "decrypt" ) ) {
                    if ( options.has( "bi" ) || options.has( "base64input" ) ) {
                        inputString = inputString();
                    } else {
                        input = inputChunk();
                    }
                }

                if ( input.length == 0 && inputString.length() == 0 ) {
                    if ( didRead ) {
                        exit( 0 );
                    } else {
                        exit( 2 );
                    }
                } else {
                    didRead = true;
                }

                if ( options.has( "bi" ) || options.has( "base64input" ) ) {
                    input = Base64.decode( inputString );
                }

                //
                // Encrypt or decrypt the chunk.
                //

                if ( options.has( "e" ) || options.has( "encrypt" ) ) {
                    output = encrypt( input );
                } else if ( options.has( "d" ) || options.has( "decrypt" ) ) {
                    output = decrypt( input );
                }

                //
                // Output the processed chunk.
                //

                if ( options.has( "bo" ) || options.has( "base64output" ) ) {
                    output = Base64.encode( output ).getBytes();
                }

                if ( !options.has( "o" ) && !options.has( "output" ) ) {
                    NtrUtil.STDOUT.print( new String( output ) );

                    if ( options.has( "bo" ) || options.has( "base64output" ) ) {
                        NtrUtil.STDOUT.println();
                    }
                } else {
                    final String filename = ( String ) (options.hasArgument( "o" ) ? options.valueOf( "o" )
                            : options.valueOf( "output" ));

                    output( output, filename );
                }

                input = new byte[0];
                inputString = "";

            }

        } catch ( Throwable t ) {
            exit( t );
        }

        exit( 0 );
    }


    private static void exit( final Throwable t ) throws IOException {
        t.printStackTrace( NtrUtil.STDERR );
        NtrUtil.STDERR.flush();

        exit( 1 );
    }


    private static void exit( final int status ) throws IOException {
        if ( status != 0 ) {
            NtrUtil.STDERR.println( usageMessage() );
        }

        NtrUtil.STDOUT.flush();
        NtrUtil.STDERR.flush();

        System.exit( status );
    }


    @NotNull
    private static String usageMessage() throws IOException {
        final InputStream inputStream = NtrUtil.class.getClassLoader().getResourceAsStream( USAGE_TXT_FILENAME );
        final BufferedReader reader = new BufferedReader( new InputStreamReader( inputStream ) );
        final StringWriter stringWriter = new StringWriter();
        final BufferedWriter writer = new BufferedWriter( stringWriter );

        String line;
        while ( (line = reader.readLine()) != null ) {
            writer.write( line );
            writer.newLine();
        }

        writer.flush();

        return stringWriter.toString();
    }


    @NotNull
    private static byte[] input() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] value = new byte[NtrUtil.maxMessageLength];
        int numRead;

        if ( (numRead = NtrUtil.STDIN.read( value )) < 0 ) {
            return new byte[0];
        }

        int totalRead = 0;

        while ( true ) {
            if ( numRead < 0 ) {
                break;
            }

            if ( numRead > 0 ) {
                totalRead += numRead;
                outputStream.write( value, 0, numRead );
            }

            if ( totalRead < NtrUtil.maxMessageLength ) {
                numRead = NtrUtil.STDIN.read( value );
            }
            else {
                break;
            }
        }

        outputStream.close();

        return outputStream.toByteArray();
    }


    @NotNull
    private static byte[] inputChunk() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] value = new byte[NtrUtil.CHUNK_LENGTH];
        int numRead;

        if ( (numRead = NtrUtil.STDIN.read( value )) < 0 ) {
            return new byte[0];
        }

        int totalRead = 0;

        while ( true ) {
            if ( numRead < 0 ) {
                break;
            }

            if ( numRead > 0 ) {
                totalRead += numRead;
                outputStream.write( value, 0, numRead );
            }

            if ( totalRead < NtrUtil.CHUNK_LENGTH ) {
                numRead = NtrUtil.STDIN.read( value );
            }
            else {
                break;
            }
        }

        outputStream.close();

        return outputStream.toByteArray();
    }


    @NotNull
    private static String inputString() throws IOException {
        final StringWriter stringWriter = new StringWriter();
        final BufferedWriter writer = new BufferedWriter( stringWriter );

        int numRead;
        char secondToLastCharRead = ' ';
        char lastCharRead = ' ';
        char[] charRead = new char[1];
        while ( (numRead = NtrUtil.STDIN_READER.read( charRead )) >= 0 ) {
            if ( numRead == 0 ) {
                continue;
            }

            writer.append( charRead[0] );

            if ( secondToLastCharRead == '=' && lastCharRead == '=' && charRead[0] == '\n' ) {
                break;
            }

            secondToLastCharRead = lastCharRead;
            lastCharRead = charRead[0];
        }

        writer.flush();

        return stringWriter.toString();
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
        } else {
            encryptionParameters = EncryptionParameters.APR2011_439_FAST;

            new File( USER_STORE_FOLDER ).mkdirs();

            final FileOutputStream outputStream = new FileOutputStream( ENCRYPTION_PARAMETERS_FILENAME );
            encryptionParameters.writeTo( outputStream );
        }

        NtrUtil.maxMessageLength = encryptionParameters.getMaxMessageLength();
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

            kp = new EncryptionKeyPair( privateKey, publicKey );
        } else {
            kp = getNTRU().generateKeyPair();

            new File( USER_STORE_FOLDER ).mkdirs();

            FileOutputStream outputStream = new FileOutputStream( PRIVATE_KEY_FILENAME );
            kp.getPrivate().writeTo( outputStream );

            outputStream = new FileOutputStream( PUBLIC_KEY_FILENAME );
            kp.getPublic().writeTo( outputStream );
        }
    }

    public static OptionParser getCliParser() {
        final OptionParser parser = new OptionParser( "?e?d?o:?v?h?u?" );

        parser.recognizeAlternativeLongOptions( true );
        parser.accepts( "encrypt" );
        parser.accepts( "decrypt" );
        parser.accepts( "bi" );
        parser.accepts( "base64input" );
        parser.accepts( "bo" );
        parser.accepts( "base64output" );
        parser.accepts( "verbose" );
        parser.accepts( "help" );
        parser.accepts( "usage" );

        return parser;
    }
}
