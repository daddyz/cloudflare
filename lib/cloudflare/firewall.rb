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
	module Firewall
		class Rule < Representation
			ACTIONS = %w(block challenge js_challenge allow log bypass).freeze
			PRODUCTS = %w(zoneLockdown uaBlock bic hot securityLevel rateLimit waf *).freeze

			def action
				value[:action]
			end

			# valid values: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf
			def products
				value[:products]
			end

			def priority
				value[:priority]
			end

			def paused
				value[:paused]
			end

			def description
				value[:description]
			end

			def ref
				value[:ref]
			end

			def filter
				value[:filter]
			end

			def to_s
				"#{configuration[:value]} - #{mode} - #{notes}"
			end
		end

		class Rules < Representation
			include Paginate

			def representation
				Rule
			end

			def set(description, action, ref, filter, products = ['*'], priority = 0, paused = false)
				raise "Unknown Action #{action}" unless Rule::ACTIONS.include?(action)
				raise "Unknown products #{products}" unless (products - Rule::PRODUCTS).size > 0

				notes ||= "cloudflare gem [#{mode}] #{Time.now.strftime('%m/%d/%y')}"

				message = self.post({
					description: description,
					action: action,
					ref: ref,
					filter: filter,
					products: products,
					priority: priority,
					paused: paused
				})

				represent_message(message)
			end

			def each_by_value(value, &block)
				each(configuration_value: value, &block)
			end
		end

		class AccessRule < Representation
			def mode
				value[:mode]
			end

			def notes
				value[:notes]
			end

			def configuration
				value[:configuration]
			end

			def to_s
				"#{configuration[:value]} - #{mode} - #{notes}"
			end
		end

		class AccessRules < Representation
			include Paginate

			def representation
				AccessRule
			end

			def set(mode, value, notes: nil, target: 'ip')
				notes ||= "cloudflare gem [#{mode}] #{Time.now.strftime('%m/%d/%y')}"

				message = self.post({
					mode: mode.to_s,
					notes: notes,
					configuration: {
						target: target,
						value: value.to_s,
					}
				})

				represent_message(message)
			end

			def each_by_value(value, &block)
				each(configuration_value: value, &block)
			end
		end
	end
end
