# 🚀 C-Like Compiler

[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Parser](https://img.shields.io/badge/Parser-Yacc/Bison-green.svg)](https://www.gnu.org/software/bison/)
[![Lexer](https://img.shields.io/badge/Lexer-Lex/Flex-orange.svg)](https://github.com/westes/flex)
[![Build](https://img.shields.io/badge/Build-Ready-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
[![3AC](https://img.shields.io/badge/Output-Three--Address--Code-red.svg)](#)

> 🎯 **A sophisticated compiler that translates C-like source code into optimized Three-Address Code (3AC) with advanced semantic analysis and scope management.**

**⚠️ IMPORTANT NOTE:** The main source files (ProjectLex.l and ProjectYacc.y) were restored from local backups due to technical issues that caused the original repository content to be lost. These files now contain the complete and final implementation.

---

## 📋 Table of Contents
- [🌟 Key Features](#-key-features)
- [🏗️ Architecture](#️-architecture)
- [📝 Language Support](#-language-support)
- [🔧 Installation](#-installation)
- [🚀 Usage](#-usage)
- [📊 Three-Address Code Generation](#-three-address-code-generation)
- [🔍 Examples](#-examples)
- [🤝 Contributing](#-contributing)

---

## 🌟 Key Features

### 🔤 **Lexical Analysis (ProjectLex.l)**
- ✅ **Complete Token Recognition**: 40+ token types including keywords, operators, and literals
- ✅ **Advanced Literals Support**: 
  - Integer literals (decimal and hexadecimal)
  - Floating-point literals (float and double)
  - String literals with escape sequences
  - Boolean literals (`true`/`false`)
  - Character literals
- ✅ **Comprehensive Operators**: Arithmetic, logical, comparison, and assignment operators
- ✅ **Comment Handling**: Multi-line C-style comments (`/* */`) with proper nesting
- ✅ **Error Recovery**: Robust error handling with `setjmp/longjmp` exception mechanism

### 🏗️ **Syntax Analysis & Parsing (ProjectYacc.y)**
- ✅ **Complete Grammar**: 50+ production rules covering full C-like syntax
- ✅ **Function Definitions**: Support for public/private access modifiers and static functions
- ✅ **Variable Declarations**: Multiple data types with initialization support
- ✅ **Control Structures**: 
  - Conditional statements (`if`, `if-else`)
  - Loops (`while`, `do-while`, `for`)
  - Block statements with proper scoping
- ✅ **Expression Evaluation**: Complex arithmetic and logical expressions with precedence
- ✅ **Array Operations**: Array indexing, assignment, and address operations
- ✅ **Pointer Support**: Pointer declarations, dereferencing, and address-of operations

### 🧠 **Semantic Analysis**
- ✅ **Multi-Level Symbol Tables**: Hierarchical scope management with nested function support
- ✅ **Type Checking**: Comprehensive type compatibility verification
- ✅ **Scope Resolution**: Proper variable and function lookup across scopes
- ✅ **Function Signature Validation**: Parameter count and type verification
- ✅ **Memory Management**: Automatic symbol table cleanup and memory deallocation

### ⚡ **Three-Address Code Generation**
- ✅ **Optimized 3AC Output**: Efficient intermediate code generation
- ✅ **Control Flow Translation**: 
  - Conditional jumps with label generation
  - Loop constructs with proper branching
  - Short-circuit evaluation for logical operators
- ✅ **Function Call Handling**: Parameter passing and return value management
- ✅ **Expression Optimization**: Temporary variable management and reuse
- ✅ **Memory Layout**: Stack frame calculation and variable offset management

### 🛡️ **Advanced Error Handling**
- ✅ **Exception Mechanism**: `TRY-CATCH` blocks for graceful error recovery
- ✅ **Detailed Error Messages**: Line number reporting and context information
- ✅ **Syntax Error Recovery**: Continues parsing after encountering errors
- ✅ **Semantic Error Detection**: Type mismatches and undeclared variable detection

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Source Code   │───▶│   Lexical        │───▶│   Token Stream  │
│   (.c-like)     │    │   Analyzer       │    │                 │
└─────────────────┘    │   (ProjectLex.l) │    └─────────────────┘
                       └──────────────────┘             │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Three-Address   │◀───│   Parser &       │◀───│   Syntax        │
│ Code (3AC)      │    │   Semantic       │    │   Analysis      │
│                 │    │   Analyzer       │    │                 │
└─────────────────┘    │   (ProjectYacc.y)│    └─────────────────┘
                       └──────────────────┘
```

---

## 📝 Language Support

### 🔑 **Keywords**
```c
if, else, while, for, do, return, var, args>>
public, private, static, void, null
bool, char, int, double, float, string
int*, char*, double*, float*  // Pointer types
```

### 🔢 **Data Types**
- **Primitive Types**: `int`, `char`, `double`, `float`, `bool`, `string`
- **Pointer Types**: `int*`, `char*`, `double*`, `float*`
- **Literals**: Integer, hexadecimal, floating-point, boolean, character, string
- **Special**: `void`, `null`

### ⚙️ **Operators**
| Category | Operators | Description |
|----------|-----------|-------------|
| **Arithmetic** | `+`, `-`, `*`, `/` | Basic math operations |
| **Assignment** | `<-` | Variable assignment |
| **Comparison** | `==`, `!=`, `<=`, `>=`, `<`, `>` | Relational operators |
| **Logical** | `&&`, `\|\|`, `!` | Boolean operations |
| **Memory** | `&`, `*` | Address-of and dereference |

### 🏗️ **Language Constructs**
- **Functions**: With access modifiers (`public`, `private`, `static`)
- **Control Flow**: `if-else`, `while`, `do-while`, `for` loops
- **Arrays**: Declaration, indexing, and manipulation
- **Pointers**: Declaration, dereferencing, and address operations
- **Scoping**: Block-level and function-level scope management

---

## 🔧 Installation

### Prerequisites
- **Flex** (Fast Lexical Analyzer)
- **Bison/Yacc** (Parser Generator)
- **GCC** (GNU Compiler Collection)
- **Make** (Build automation tool)

### 🪟 Windows Installation
```powershell
# Install using Chocolatey
choco install winflexbison3
choco install mingw

# Or download from:
# https://github.com/lexxmark/winflexbison/releases
# https://www.mingw-w64.org/downloads/
```

### 🐧 Linux Installation
```bash
# Ubuntu/Debian
sudo apt-get install flex bison gcc make

# CentOS/RHEL
sudo yum install flex bison gcc make

# Arch Linux
sudo pacman -S flex bison gcc make
```

### 🍎 macOS Installation
```bash
# Using Homebrew
brew install flex bison gcc make

# Using MacPorts
sudo port install flex bison gcc make
```

---

## 🚀 Usage

### 🔨 **Building the Compiler**
```bash
# Generate lexer
flex ProjectLex.l

# Generate parser
bison -d ProjectYacc.y
# or
yacc -d ProjectYacc.y

# Compile the compiler
gcc -o compiler lex.yy.c y.tab.c -lfl
```

### ▶️ **Running the Compiler**
```bash
# Compile a source file
./compiler < input.c

# Or with input redirection
./compiler input.c

# View generated 3AC
./compiler input.c > output.3ac
```

### 📄 **Sample Input File**
```c
// sample.c
public int main() {
    var int x <- 10;
    var int y <- 20;
    var int result;
    
    if (x < y) {
        result <- x + y;
    } else {
        result <- x - y;
    }
    
    return result;
}
```

---

## 📊 Three-Address Code Generation

### 🎯 **3AC Format**
The compiler generates optimized three-address code with the following characteristics:

- **Temporary Variables**: `t1`, `t2`, `t3`, ...
- **Labels**: `L1`, `L2`, `L3`, ...
- **Operations**: Binary and unary operations
- **Control Flow**: Conditional and unconditional jumps

### 📋 **Sample 3AC Output**
```
// For the sample input above
ENTER main, 12          // Function entry with stack size
t1 = 10                 // x <- 10
t2 = 20                 // y <- 20
t3 = t1 < t2           // Comparison
if t3 goto L1          // Conditional jump
t4 = t1 - t2           // else branch
goto L2
L1: t4 = t1 + t2       // if branch
L2: return t4          // Return result
EXIT main              // Function exit
```

### 🔄 **Optimization Features**
- **Temporary Reuse**: Efficient temporary variable management
- **Dead Code Elimination**: Removes unreachable code
- **Constant Folding**: Evaluates constant expressions at compile time
- **Short-Circuit Evaluation**: Optimizes logical expressions

---

## 🔍 Examples

### 🔄 **Loop Example**
```c
// Input
public void fibonacci(int n) {
    var int a <- 0;
    var int b <- 1;
    var int i <- 0;
    
    while (i < n) {
        var int temp <- a + b;
        a <- b;
        b <- temp;
        i <- i + 1;
    }
}
```

```
// Generated 3AC
ENTER fibonacci, 16
t1 = 0                  // a <- 0
t2 = 1                  // b <- 1
t3 = 0                  // i <- 0
L1: t4 = t3 < param1    // while condition
if_false t4 goto L2
t5 = t1 + t2           // temp <- a + b
t1 = t2                // a <- b
t2 = t5                // b <- temp
t3 = t3 + 1            // i <- i + 1
goto L1
L2: EXIT fibonacci
```

### 🎯 **Function Call Example**
```c
// Input
public int add(int a, int b) {
    return a + b;
}

public int main() {
    var int result <- add(5, 3);
    return result;
}
```

```
// Generated 3AC
ENTER add, 8
t1 = param1 + param2
return t1
EXIT add

ENTER main, 4
param1 = 5
param2 = 3
call add, 2
t2 = retval
return t2
EXIT main
```

---

## 🤝 Contributing

### 🐛 **Bug Reports**
If you find any bugs or issues, please:
1. Check existing issues first
2. Create a detailed bug report with:
   - Input code that causes the issue
   - Expected vs actual behavior
   - System information

### 💡 **Feature Requests**
We welcome suggestions for:
- New language features
- Optimization improvements
- Better error messages
- Additional output formats

### 🔧 **Development**
```bash
# Fork the repository
git clone https://github.com/yourusername/C-Like-Compiler.git
cd C-Like-Compiler

# Make your changes
# Test thoroughly
# Submit a pull request
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Flex/Lex** - Fast lexical analyzer generator
- **Bison/Yacc** - Parser generator
- **GNU Compiler Collection** - For compilation tools
- **The Dragon Book** - Compilers: Principles, Techniques, and Tools

---

<div align="center">

**⭐ Star this repository if you find it helpful! ⭐**

*Built with ❤️ for compiler enthusiasts*

</div>
