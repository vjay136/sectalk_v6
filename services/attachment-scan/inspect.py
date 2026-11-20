"""Read only bounded document metadata. Never launch or follow document actions."""
import io
import json
import resource
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

INPUT_BYTES = 4 * 1024 * 1024
EXPANDED_BYTES = 12 * 1024 * 1024
METADATA_BYTES = 256 * 1024
TYPES = {
    'docx': ('word/document.xml', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'),
    'docm': ('word/document.xml', 'application/vnd.ms-word.document.macroEnabled.main+xml'),
    'xlsx': ('xl/workbook.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'),
    'xlsm': ('xl/workbook.xml', 'application/vnd.ms-excel.sheet.macroEnabled.main+xml'),
    'pptx': ('ppt/presentation.xml', 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'),
    'pptm': ('ppt/presentation.xml', 'application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml'),
}
CONTENT_TYPES = '{http://schemas.openxmlformats.org/package/2006/content-types}'
RELATIONSHIPS = '{http://schemas.openxmlformats.org/package/2006/relationships}'
OFFICE_LINK_TYPES = {
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument',
    'http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument',
}


def require(condition):
    if not condition:
        raise ValueError('Unsupported document structure')


def xml(raw):
    require(len(raw) <= METADATA_BYTES)
    source = raw.decode('utf-8-sig')
    require('\x00' not in source and '<!DOCTYPE' not in source.upper() and '<!ENTITY' not in source.upper())
    return ET.fromstring(source)


def office(data, kind):
    main, content_type = TYPES[kind]
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 256)
        trailer = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
        require(trailer >= 0 and trailer + 22 + len(archive.comment) == len(data))
        require(min(entry.header_offset for entry in entries) == 0)
        require(sum(entry.file_size for entry in entries) <= EXPANDED_BYTES)
        names = set()
        metadata = {}
        for entry in entries:
            name = entry.orig_filename
            segments = name.rstrip('/').split('/')
            require(len(name) <= 240 and not any(ord(char) < 32 or char in '\\:' for char in name))
            require(all(part not in ('', '.', '..') for part in segments) and name.casefold() not in names)
            require(not stat.S_ISLNK(entry.external_attr >> 16) and not entry.flag_bits & 1)
            require(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            names.add(name.casefold())
            if name == '[Content_Types].xml' or name.lower().endswith('.rels') or name == main:
                require(entry.file_size <= METADATA_BYTES)
            with archive.open(entry) as stream:
                clear = stream.read(entry.file_size + 1)
            require(len(clear) == entry.file_size)
            if name == '[Content_Types].xml' or name.lower().endswith('.rels') or name == main:
                metadata[name] = xml(clear)
        types = metadata['[Content_Types].xml']
        family, extension = main.split('/')
        document = extension.removesuffix('.xml')
        family_namespace = {'word': 'wordprocessingml', 'xl': 'spreadsheetml', 'ppt': 'presentationml'}[family]
        require(types.tag == CONTENT_TYPES + 'Types' and metadata[main].tag in (
            '{http://schemas.openxmlformats.org/' + family_namespace + '/2006/main}' + document,
            '{http://purl.oclc.org/ooxml/' + family_namespace + '/main}' + document,
        ))
        overrides = [node.get('ContentType') for node in types.findall(CONTENT_TYPES + 'Override')
                     if node.get('PartName') == '/' + main]
        require(overrides == [content_type])
        root = metadata['_rels/.rels']
        require(root.tag == RELATIONSHIPS + 'Relationships')
        main_links = [node for node in root.findall(RELATIONSHIPS + 'Relationship')
                      if node.get('Type') in OFFICE_LINK_TYPES]
        require(len(main_links) == 1 and main_links[0].get('TargetMode', 'Internal') == 'Internal'
                and main_links[0].get('Target') in (main, '/' + main))

        linked = False
        for filename, tree in metadata.items():
            if filename.lower().endswith('.rels'):
                require(tree.tag == RELATIONSHIPS + 'Relationships')
                linked |= any(node.get('TargetMode') == 'External' for node in tree.findall(RELATIONSHIPS + 'Relationship'))
        if kind.endswith('m') or any(name.endswith('/vbaproject.bin') or '/macrosheets/' in name for name in names):
            return 'document_macro_marker'
        if any('/embeddings/' in name or '/activex/' in name for name in names):
            return 'embedded_document_marker'
        if linked:
            return 'embedded_link_marker'
    return None


def pdf(data):
    with tempfile.NamedTemporaryFile() as source, tempfile.TemporaryFile() as output:
        source.write(data)
        source.flush()
        result = subprocess.run(
            ['/usr/bin/qpdf', '--json', '--json-key=qpdf', '--json-stream-data=none', source.name],
            stdout=output, stderr=subprocess.DEVNULL, check=False, timeout=4,
        )
        require(result.returncode == 0 and output.tell() <= INPUT_BYTES)
        output.seek(0)
        objects = json.load(output)['qpdf']
    names = set()
    pending = [objects]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            names.update(key for key in node if key.startswith('/'))
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, str) and node.startswith('/'):
            names.add(node)
    if names & {'/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA'}:
        return 'script_marker'
    if names & {'/EmbeddedFile', '/EmbeddedFiles', '/RichMedia', '/XFA'}:
        return 'embedded_document_marker'
    if '/URI' in names:
        return 'embedded_link_marker'
    return None


def main():
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (4, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (INPUT_BYTES,) * 2)
    kind = sys.argv[1]
    data = sys.stdin.buffer.read(INPUT_BYTES + 1)
    require(0 < len(data) <= INPUT_BYTES)
    reason = pdf(data) if kind == 'pdf' else office(data, kind)
    print(json.dumps({'reason': reason}))


if __name__ == '__main__':
    try:
        main()
    except (KeyError, ValueError, RuntimeError, RecursionError, ET.ParseError, zipfile.BadZipFile):
        sys.exit(2)
