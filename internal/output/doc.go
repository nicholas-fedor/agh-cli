// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package output renders the results of the commands.
//
// It writes aligned tables, status reports, and one-line outcomes, and it lays
// out the tables of a run that selected several instances. It also declares the
// columns each rewrite table can be sorted by. Every writer takes an [io.Writer],
// so the command decides which stream receives the output. A secret never
// reaches a writer, because the results it renders never carry one.
package output
