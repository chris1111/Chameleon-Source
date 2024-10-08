/* Copyright (C) 1991, 1995 Free Software Foundation, Inc.

This library is free software; you can redistribute it and/or modify 
it under theterms of the GNU General Public License as published 
by the Free Software Foundation; either version 2, or (at your option)
any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU CC; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

As a special exception, if you link this library with files
compiled with a GNU compiler to produce an executable, this does not cause
the resulting executable to be covered by the GNU General Public License.
This exception does not however invalidate any other reasons why
the executable file might be covered by the GNU General Public License. */

#include "libsa.h"

extern double atof ();

double strtod (nptr, enptr)
	char *nptr;
	char **enptr;
{
	char *p;

	if (enptr == (char **)0)
		return atof (nptr);

	p = nptr;

	while (isspace (*p))
		++p;

	if (*p == '+' || *p == '-')
		++p;

	/* INF or INFINITY.  */
	if ((p[0] == 'i' || p[0] == 'I')
		&& (p[1] == 'n' || p[1] == 'N')
		&& (p[2] == 'f' || p[2] == 'F'))
	{
		if ((p[3] == 'i' || p[3] == 'I')
			&& (p[4] == 'n' || p[4] == 'N')
			&& (p[5] == 'i' || p[5] == 'I')
			&& (p[6] == 't' || p[6] == 'T')
			&& (p[7] == 'y' || p[7] == 'Y'))
		{
			*enptr = p + 7;
			return atof (nptr);
		}
		else
		{
			*enptr = p + 3;
			return atof (nptr);
		}
	}

	/* NAN or NAN(foo).  */
	if ((p[0] == 'n' || p[0] == 'N')
		&& (p[1] == 'a' || p[1] == 'A')
		&& (p[2] == 'n' || p[2] == 'N'))
	{
		p += 3;
		if (*p == '(')
		{
			++p;
			while (*p != '\0' && *p != ')')
				++p;
			if (*p == ')')
				++p;
		}
		*enptr = p;
		return atof (nptr);
	}

	/* digits, with 0 or 1 periods in it.  */
	if (isdigit (*p) || *p == '.')
	{
		int got_dot = 0;
		while (isdigit (*p) || (!got_dot && *p == '.'))
		{
			if (*p == '.')
				got_dot = 1;
			++p;
		}

		/* Exponent.  */
		if (*p == 'e' || *p == 'E')
		{
			int i;
			i = 1;
			if (p[i] == '+' || p[i] == '-')
				++i;
			if (isdigit (p[i]))
			{
				while (isdigit (p[i]))
					++i;
				*enptr = p + i;
				return atof (nptr);
			}
		}
		*enptr = p;
		return atof (nptr);
	}
	/* Didn't find any digits.  Doesn't look like a number.  */
	*enptr = nptr;
	return 0.0;
}
