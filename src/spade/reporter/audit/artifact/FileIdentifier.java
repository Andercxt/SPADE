/*
 --------------------------------------------------------------------------------
 SPADE - Support for Provenance Auditing in Distributed Environments.
 Copyright (C) 2015 SRI International

 This program is free software: you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------------
 */

package spade.reporter.audit.artifact;

import spade.reporter.audit.OPMConstants;

public class FileIdentifier extends PathIdentifier{

	private static final long serialVersionUID = 4297464246093502916L;

	public FileIdentifier(String path, String rootFSPath){
		super(path, rootFSPath);
	}
	
	public String getSubtype(){
		return OPMConstants.SUBTYPE_FILE;
	}
}
