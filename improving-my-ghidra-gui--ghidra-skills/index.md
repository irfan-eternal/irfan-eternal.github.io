# Improving My Ghidra GUI + Ghidra Skills

<img src="ghidra.png" alt="Ghidra" width="400"/>

Hi all, Today I am writitng this Post to let you know How i Improved  My Ghidra GUI & Ghidra Skills. We will be  Discussing the Below Topics

1) Customizing Code Browser
2) Key Bindings
3) Ghidra Extensions
4) Ghidra Scripting

## Customizing Code Browser

Ghidra CodeBrowser has many Windows which helps in our analysis. My Aim was to reduce switchig Between Windows as less as possible. So I found the Windows i used the most and Combined them in the Main CodeBrowser Window.
The Sections in My CodeBrowser Windows are

1) Symbol Tree
2) Data Type Manager
3) Listing Window
4) Function Graph
5) Function Call Graph
6) Decompiler
7) Defined Strings
8) Console
9) Bookmarks
10) Python

I won't Recommend you to use this Same Sections. Try to find the Windows you use the most and Combine them in the CodeBrowser. You Can add this Windows by Visiting Windows > "Windows you want to View". After that Adjust them by Dragging the Windows

Ghidra Lets you Cutomize the Code Browser by Visiting Edit > Tool Options.An option which helped me a lot is Cursor Text Highlighting
Cursor Text Highlighting : Edit > Tool Options > Cursor Text Highlight > Mouse Button to Activate : LEFT (This will Highlight the Ocuurence of a Selected string in Listing/Decompiler Window)

## Key Bindings

Ghidra Key Bindings helps you to perform Actions related to Ghidra. Ghidra Has So many Default KeyBindings [Full List of Key Bindings](https://ghidra-sre.org/CheatSheet.html). Ghidra Also help you to Add Custom KeyBindings by Visiting Edit > Tool Options > Key Binding.
Here is a List of Key Bindings(Default + Custom) I use the most
1) L : Edit Label / Rename Function / Rename Variable
2) Ctrl + L : Retype Variable
3) T: Choose Data Type
4) X: Show Xrefs TO
5) Shift + [ = Create Structure
6) F3 = Edit Function Signature
7) C = Clear Code
8) D = Disassemble

Find the Actions you perform the Most. look if there is a Key Binding for it. if not add a Custom Key Binding. Setting Key Bindings for Most used Functions is a good Practice


## Ghidra Extensions

Ghidrathon








