package com.redhat.pkidog;

public class WatchdogClient {

    static boolean tryLoad( String filename )
    {
        try {
            System.load( filename );
        } catch( Exception e ) {
            return false;
        } catch( UnsatisfiedLinkError e ) {
            return false;
        }

        return true;
    }

    // Load native library
    static {
        boolean mNativeLibrariesLoaded = false;
        // Check for 64-bit library availability
        // prior to 32-bit library availability.
        mNativeLibrariesLoaded =
            tryLoad( "/usr/lib64/pkidog-jni/libpkidog-jni.so" );
        if( mNativeLibrariesLoaded ) {
            System.out.println( "64-bit libpkidog-jni library loaded" );
        } else {
            // REMINDER:  May be trying to run a 32-bit app
            //            on 64-bit platform.
            mNativeLibrariesLoaded =
                tryLoad( "/usr/lib/pkidog-jni/libpkidog-jni.so" );
            if( mNativeLibrariesLoaded ) {
                System.out.println( "32-bit pkidog-jni library loaded");
            } else {
                System.out.println( "FAILED loading pkidog-jni library!");
                System.exit( -1 );
            }
        }
    }

    public static native int init();
    public static native int sendEndInit(int numprocs);
    public static native String getPassword(String prompt, int serial);

}







   

