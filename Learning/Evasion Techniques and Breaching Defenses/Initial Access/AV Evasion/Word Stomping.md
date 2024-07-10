
Use FlexHex to open as "OLE Compound File" a word document that would contain the Macro.

After it loads, click on the "Macros" -> "PROJECT" on the navigation tab

Highlight "Module=NewMacros" in the hex editor and replace "Edit" -> "Insert Zero Block" so FlexHex inserts nullbytes

The document holds a compiled version of the VBA macro known as P-code

P-code needs to run on the same Word version as the one it was created in

If the document is opened on a different version which the macro was created, the P-code is ignored and the textual macro is run instead

Now, to stomp the document, go to Macros -> VBA -> NewMacros

Find "Attribute VB_Name = 'New Macros'"

Highlight it, and hightlight everything down until the last bytes

Now click on "Edit" -> "Insert Zero Block" so FlexHex inserts nullbytes