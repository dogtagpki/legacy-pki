// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA
//
// Copyright (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.redhat.nuxwdog;

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
            tryLoad( "/usr/lib64/nuxwdog-jni/libnuxwdog-jni.so" );
        if( mNativeLibrariesLoaded ) {
            System.out.println( "64-bit libnuxwdog-jni library loaded" );
        } else {
            // REMINDER:  May be trying to run a 32-bit app
            //            on 64-bit platform.
            mNativeLibrariesLoaded =
                tryLoad( "/usr/lib/nuxwdog-jni/libnuxwdog-jni.so" );
            if( mNativeLibrariesLoaded ) {
                System.out.println( "32-bit nuxwdog-jni library loaded");
            } else {
                System.out.println( "FAILED loading nuxwdog-jni library!");
                System.exit( -1 );
            }
        }
    }

    public static native int init();
    public static native int sendEndInit(int numprocs);
    public static native String getPassword(String prompt, int serial);

}







   

