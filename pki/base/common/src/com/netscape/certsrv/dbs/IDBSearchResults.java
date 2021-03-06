// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.dbs;


import java.util.Enumeration;
 

/**
 * A class represents the search results. A search
 * results object contain a enumeration of
 * Java objects that are just read from the database.
 *
 * @version $Revision$, $Date$ 
 */
public interface IDBSearchResults extends Enumeration {

    /**
     * Checks if any element is available.
     *
     * @return true if there is more elements
     */
    public boolean hasMoreElements();

    /**
     * Retrieves next element.
     *
     * @return next element
     */
    public Object nextElement();
}
