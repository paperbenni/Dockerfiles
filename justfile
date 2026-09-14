shell_scripts := `find . -type f -name '*.sh' -not -path './.git/*' -print | sed 's#^./##' | sort | tr '\n' ' '`

default: check

# Run syntax, static-analysis, and formatting checks for every shell script.
check:
    @for file in {{shell_scripts}}; do \
        head -n1 "$file" | grep -Eq '^#!.*(bash|/sh)$' || { \
            echo "unsupported or missing shell shebang: $file" >&2; \
            exit 1; \
        }; \
        case "$(head -n1 "$file")" in \
            *bash) bash -n "$file" ;; \
            *) sh -n "$file" ;; \
        esac; \
    done
    shellcheck {{shell_scripts}}
    shfmt -d -i 4 -ci -bn {{shell_scripts}}

# Format every shell script in place.
fmt:
    shfmt -w -i 4 -ci -bn {{shell_scripts}}

alias format := fmt
