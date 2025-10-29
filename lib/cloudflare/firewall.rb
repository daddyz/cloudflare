# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2019-2024, by Samuel Williams.
# Copyright, 2019, by Rob Widmer.

require_relative "representation"
require_relative "paginate"

module Cloudflare
	module Firewall
		class Rule < Representation

                        ACTIONS = %w(block challenge js_challenge allow log bypass).freeze
			PRODUCTS = %w(zoneLockdown uaBlock bic hot securityLevel rateLimit waf *).freeze

			def action
				result[:action]
			end

			# valid values: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf
			def products
				result[:products]
			end

			def priority
				result[:priority]
			end

			def paused
				result[:paused]
			end

			def description
				result[:description]
			end

			def ref
				result[:ref]
			end

			def filter
				result[:filter]
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
				result[:mode]
                        end

                        include Async::REST::Representation::Mutable
			
			ACTIONS = %w(block challenge js_challenge allow log bypass).freeze
			PRODUCTS = %w(zoneLockdown uaBlock bic hot securityLevel rateLimit waf *).freeze

			def action
				result[:action]
			end

			# valid values: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf
			def products
				result[:products]
			end

			def priority
				result[:priority]
			end

			def paused
				result[:paused]
			end

			def description
				result[:description]
			end

			def ref
				result[:ref]
			end

			def filter
				result[:filter]
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

	end
end
