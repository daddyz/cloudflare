# frozen_string_literal: true

# Copyright, 2018, by Samuel G. D. Williams. <http://www.codeotaku.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

require_relative 'representation'
require_relative 'paginate'

module Cloudflare
	module Filter
		class Filter < Representation
			def expression
				value[:expression]
			end

			def id
				value[:id]
			end

			def description
				value[:description]
			end

			def ref
				value[:ref]
			end
		end

		class Filters < Representation
			include Paginate

			def representation
				Filter
			end

			def set(expression, description, ref)
				message = self.post({
					expression: expression.to_s,
					description: description,
					ref: ref
				})

				represent_message(message)
			end

			def update(id, expression, description, ref)
				self.with(Filter, path: "#{id}").put({
																								id: id,
																								expression: expression.to_s,
																								description: description,
																								ref: ref
																							})
				self
			end
		end
	end
end
