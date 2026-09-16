shell_scripts := `find . -type f -name '*.sh' -not -path './.git/*' -print | sed 's#^./##' | sort | tr '\n' ' '`

default: check

# Run all static checks and tests.
check: check-shell check-openfortivpn

# Run syntax, static-analysis, and formatting checks for every shell script.
check-shell:
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

# Compile-check and unit-test the openfortivpn Python entrypoint.
# Tools are pinned and fetched via uvx so local runs match CI.
check-openfortivpn:
    uvx ruff@0.16.7 check --no-cache openfortivpn/
    uvx ruff@0.16.7 format --no-cache --check openfortivpn/docker-entrypoint.py openfortivpn/test_entrypoint.py
    uvx ty@0.0.81 check openfortivpn/
    uvx pytest@9.1.1 -p no:cacheprovider openfortivpn/test_entrypoint.py -q
