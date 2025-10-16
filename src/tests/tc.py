from pathlib import Path
import ast
import html as html_module
import os
import re
from datetime import datetime

def main():
    home = Path.home()
    client_dir = home / 'Code' / 'sssd-qe' / 'client'
    intg_dir = home / 'Code' / 'sssd' / 'src' / 'tests' / 'intg'
    system_dir = home / 'Code' / 'sssd' / 'src' / 'tests' / 'system'
    multihost_dir = home / 'Code' / 'sssd' / 'src' / 'tests' / 'multihost'
    planned_dir = home / 'Code' / 'sssd' / 'src' / 'tests' / 'planned'

    def find_files(base_dir):
        files = []
        for p in base_dir.rglob('*'):
            if p.is_file() and p.suffix in ['.py', '.sh']:
                rel = p.relative_to(base_dir)
                parents = list(rel.parents)
                if any(part.name.startswith('.') for part in parents):
                    continue
                if p.suffix == '.py' and not p.name.startswith('test_'):
                    continue
                if p.name in ['cleanup.sh', 'setup.sh']:
                    continue
                files.append(str(rel))
        return files

    client_files = [(f, 'client') for f in find_files(client_dir)]
    intg_files = [(f, 'intg') for f in find_files(intg_dir)]
    system_files = [(f, 'system') for f in find_files(system_dir)]
    multihost_files = [(f, 'multihost') for f in find_files(multihost_dir)]
    planned_files = [(f, 'planned') for f in find_files(planned_dir)]

    def get_url(rel, kind):
        base = {
            'client': 'https://gitlab.cee.redhat.com/sssd/sssd-qe/-/blob/main/client',
            'intg': 'https://github.com/SSSD/sssd/blob/master/src/tests/intg',
            'system': 'https://github.com/SSSD/sssd/blob/master/src/tests/system',
            'multihost': 'https://github.com/SSSD/sssd/blob/master/src/tests/multihost',
            'planned': 'https://github.com/SSSD/sssd/blob/master/src/tests/planned'
        }
        return f"{base[kind]}/{rel}"

    def get_test_names(full_path):
        tests = []
        if full_path.suffix == '.py':
            try:
                with open(full_path, 'r') as f:
                    tree = ast.parse(f.read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                        doc = ast.get_docstring(node) or ""
                        tests.append((node.name, doc))
            except Exception:
                pass
        else:  # .sh
            try:
                with open(full_path, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        match = re.match(r'\s*rlPhaseStartTest\s+"([^"]+)"', line)
                        if match:
                            name = match.group(1)
                            tests.append((name, ""))
            except Exception:
                pass
        return tests

    def count_client_tests():
        total = 0
        for f, _ in client_files:
            path = client_dir / f
            tests = get_test_names(path)
            total += len(tests)
        return total

    def count_intg_tests():
        total = 0
        for f, _ in intg_files:
            path = intg_dir / f
            tests = get_test_names(path)
            total += len(tests)
        return total

    def count_multihost_tests():
        total = 0
        for f, _ in multihost_files:
            path = multihost_dir / f
            tests = get_test_names(path)
            total += len(tests)
        return total

    def count_planned_tests():
        total = 0
        for f, _ in planned_files:
            path = planned_dir / f
            tests = get_test_names(path)
            total += len(tests)
        return total

    def count_system_tests():
        total = 0
        for f, _ in system_files:
            path = system_dir / f
            tests = get_test_names(path)
            total += len(tests)
        return total

    existing_total = count_client_tests() + count_intg_tests() + count_multihost_tests()
    current_total = count_planned_tests() + count_system_tests()
    generated_date = datetime.now().strftime("%B %d, %Y")
    file_date = datetime.now().strftime("%Y-%m-%d")

    def build_tree(files_list):
        tree = {'dirs': {}, 'files': []}
        for rel, kind in files_list:
            parts = rel.split(os.sep)
            current = tree
            for part in parts[:-1]:
                if part not in current['dirs']:
                    current['dirs'][part] = {'dirs': {}, 'files': []}
                current = current['dirs'][part]
            current['files'].append((parts[-1], rel, kind))
        return tree

    def render_tree(tree, get_full_path_func):
        def render_node(node):
            node_html = ''
            dir_keys = sorted(node['dirs'].keys())
            file_tuples = sorted(node['files'], key=lambda x: x[0])
            all_items = [k for k in dir_keys] + [ft[0] for ft in file_tuples]
            for i, item in enumerate(all_items):
                if item in node['dirs']:
                    node_html += f'<li><details><summary>{item}/</summary>'
                    node_html += render_node(node['dirs'][item])
                    node_html += '</details></li>'
                else:
                    for fname, frel, fkind in file_tuples:
                        if fname == item:
                            full_path = get_full_path_func(frel, fkind)
                            url = get_url(frel, fkind)
                            tests = get_test_names(full_path)
                            test_count = len(tests)
                            node_html += f'<li><details><summary><a href="{url}">{item} ({test_count})</a></summary>'
                            if tests:
                                node_html += '<ul>'
                                for tname, tdoc in tests:
                                    if tdoc:
                                        escaped = html_module.escape(tdoc, quote=True)
                                        node_html += f'<li><details><summary>{tname}</summary><pre>{escaped}</pre></details></li>'
                                    else:
                                        node_html += f'<li>{tname}</li>'
                                node_html += '</ul>'
                            node_html += '</details></li>'
                            break
            return '<ul>' + node_html + '</ul>' if node_html else ''
        return render_node(tree)

    client_tree = build_tree(client_files)
    def get_client_path(rel, _):
        return client_dir / rel
    client_html = render_tree(client_tree, get_client_path)

    intg_tree = build_tree(intg_files)
    def get_intg_path(rel, _):
        return intg_dir / rel
    intg_html = render_tree(intg_tree, get_intg_path)

    multihost_tree = build_tree(multihost_files)
    def get_multihost_path(rel, _):
        return multihost_dir / rel
    multihost_html = render_tree(multihost_tree, get_multihost_path)

    # Flat expanded list for system files
    system_html = '<ul>\n'
    for rel, _ in sorted(system_files, key=lambda x: x[0]):
        full_path = system_dir / rel
        url = get_url(rel, 'system')
        tests = get_test_names(full_path)
        test_count = len(tests)
        system_html += f'<li><details open><summary><a href="{url}">{rel} ({test_count})</a></summary>\n'
        if tests:
            system_html += '<ul>\n'
            for tname, tdoc in tests:
                if tdoc:
                    escaped = html_module.escape(tdoc, quote=True)
                    system_html += f'<li><details><summary>{tname}</summary><pre>{escaped}</pre></details></li>\n'
                else:
                    system_html += f'<li>{tname}</li>\n'
            system_html += '</ul>\n'
        system_html += '</details></li>\n'
    system_html += '</ul>\n'

    planned_tree = build_tree(planned_files)
    def get_planned_path(rel, _):
        return planned_dir / rel
    planned_html = render_tree(planned_tree, get_planned_path)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Cases</title>
    </head>
    <body>
        <h1>Test Cases</h1>
        <p>Generated on: {generated_date}</p>
        <p>Total Existing Test Cases: {existing_total}</p>
        <p>Total Current Test Cases: {current_total}</p>
        <h2>Existing:</h2>
        <h3>BASH</h3>
        {client_html}
        <h3>intg</h3>
        {intg_html}
        <h3>multihost</h3>
        {multihost_html}
        <h2>Current:</h2>
        <h3>planned</h3>
        {planned_html}
        <h3>system</h3>
        {system_html}
    </body>
    </html>
    """

    report_path = Path(f'{file_date}-test-case-status.html')
    with open(report_path, 'w') as f:
        f.write(html_content)

    print(f'HTML report created: {report_path}')

if __name__ == '__main__':
    main()