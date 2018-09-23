/*
 * Copyright (C) David Disseldorp 2018
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) version 3.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 */
#include <stdint.h>
#include <string.h>

#include "cli_util.h"
#include "cli_mime.h"

struct cli_mime_map {
	char *file_ext;
	char *mime_type;
};

/*
 * file extension to mime type map, based on https://developer.mozilla.org
 * -> /en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
 */
static const struct cli_mime_map cli_mime_file_map[] = {
	{".aac", "audio/aac"},
	{".abw", "application/x-abiword"},
	{".arc", "application/octet-stream"},
	{".avi", "video/x-msvideo"},
	{".azw", "application/vnd.amazon.ebook"},
	{".bin", "application/octet-stream"},
	{".bmp", "image/bmp"},
	{".bz", "application/x-bzip"},
	{".bz2", "application/x-bzip2"},
	{".csh", "application/x-csh"},
	{".css", "text/css"},
	{".csv", "text/csv"},
	{".doc", "application/msword"},
	{".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	{".eot", "application/vnd.ms-fontobject"},
	{".epub", "application/epub+zip"},
	{".es", "application/ecmascript"},
	{".gif", "image/gif"},
	{".htm", "text/html"},
	{".html", "text/html"},
	{".ico", "image/x-icon"},
	{".ics", "text/calendar"},
	{".jar", "application/java-archive"},
	{".jpeg", "image/jpeg"},
	{".jpg", "image/jpeg"},
	{".js", "application/javascript"},
	{".json", "application/json"},
	{".mid", "audio/midi audio/x-midi"},
	{".midi", "audio/midi audio/x-midi"},
	{".mpeg", "video/mpeg"},
	{".mpkg", "application/vnd.apple.installer+xml"},
	{".odp", "application/vnd.oasis.opendocument.presentation"},
	{".ods", "application/vnd.oasis.opendocument.spreadsheet"},
	{".odt", "application/vnd.oasis.opendocument.text"},
	{".oga", "audio/ogg"},
	{".ogv", "video/ogg"},
	{".ogx", "application/ogg"},
	{".otf", "font/otf"},
	{".png", "image/png"},
	{".pdf", "application/pdf"},
	{".ppt", "application/vnd.ms-powerpoint"},
	{".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
	{".rar", "application/x-rar-compressed"},
	{".rtf", "application/rtf"},
	{".sh", "application/x-sh"},
	{".svg", "image/svg+xml"},
	{".swf", "application/x-shockwave-flash"},
	{".tar", "application/x-tar"},
	{".tif", "image/tiff"},
	{".tiff", "image/tiff"},
	{".ts", "application/typescript"},
	{".ttf", "font/ttf"},
	{".txt", "text/plain"},
	{".vsd", "application/vnd.visio"},
	{".wav", "audio/wav"},
	{".weba", "audio/webm"},
	{".webm", "video/webm"},
	{".webp", "image/webp"},
	{".woff", "font/woff"},
	{".woff2", "font/woff2"},
	{".xhtml", "application/xhtml+xml"},
	{".xls", "application/vnd.ms-excel"},
	{".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	{".xml", "application/xml"},
	{".xul", "application/vnd.mozilla.xul+xml"},
	{".zip", "application/zip"},
	{".3gp", "video/3gpp"},
	{".3g2", "video/3gpp2"},
	{".7z", "application/x-7z-compressed"},
};

const char *
cli_mime_type_lookup(const char *file_path)
{
	size_t file_len;
	int i;

	if (file_path == NULL) {
		return NULL;
	}

	file_len = strlen(file_path);
	if (file_len == 0) {
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(cli_mime_file_map); i++) {
		size_t ext_len = strlen(cli_mime_file_map[i].file_ext);

		if (ext_len > file_len) {
			continue;
		}

		if (!strcmp(cli_mime_file_map[i].file_ext,
			    &file_path[file_len - ext_len])) {
			return cli_mime_file_map[i].mime_type;
		}
	}

	return NULL;
}
