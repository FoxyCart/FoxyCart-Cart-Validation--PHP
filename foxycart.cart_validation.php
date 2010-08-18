<?php
/**
 * FoxyCart_Helper
 *
 * @author FoxyCart.com
 * @copyright FoxyCart.com LLC, 2010
 * @version 0.7.0.20100730
 * @license http://www.gnu.org/licenses/lgpl.html GNU Lesser General Public License
 * @example http://wiki.foxycart.com/docs/cart/validation
 * 
 * Requirements:
 *   - Form "code" values should not have leading or trailing whitespace.
 *   - Cannot use double-pipes in an input's name
 *   - Empty textareas are assumed to be "open"
 */
class FoxyCart_Helper {
	/**
	 * API Key (Secret)
	 *
	 * @var string
	 **/
	private static $secret = 'ENTER YOUR KEY HERE';

	/**
	 * Cart URL
	 *
	 * @var string
	 **/
	// protected static $cart_url = 'https://yourdomain.foxycart.tld/cart';
	protected static $cart_url = 'https://YOURDOMAIN.foxycart.tld/cart';


	/**
	 * Cart Excludes
	 *
	 * Arrays of values and prefixes that should be ignored when signing links and forms.
	 * @var array
	 */
	protected static $cart_excludes = array(
		// Cart values
		'cart', 'fcsid', 'empty', 'coupon', 'output', 'sub_token', 'redirect', 'callback', '_',
		// Checkout pre-population values
		'customer_email', 'customer_first_name', 'customer_last_name', 'customer_address1', 'customer_address2',
		'customer_city', 'customer_state', 'customer_postal_code', 'customer_country', 'customer_phone', 'customer_company',
		'shipping_first_name', 'shipping_last_name', 'shipping_address1', 'shipping_address2',
		'shipping_city', 'shipping_state', 'shipping_postal_code', 'shipping_country', 'shipping_phone', 'shipping_company',
	);
	protected static $cart_excludes_prefixes = array(
		'h:', 'x:', '__',
	);

	/**
	 * Debugging
	 *
	 * Set to $debug to TRUE to enable debug logging.
	 *
	 */
	protected static $debug = FALSE;
	protected static $log = array();


	/**
	 * "Link Method": Generate HMAC SHA256 for GET Query Strings
	 *
	 * Notes: Can't parse_str because PHP doesn't support non-alphanumeric characters as array keys.
	 * @return string
	 **/
	public static function fc_hash_querystring($qs, $output = TRUE) {
		self::$log[] = '<strong>Signing link</strong> with data: '.htmlspecialchars(substr($qs, 0, 150)).'...';
		$fail = self::$cart_url.'?'.$qs;

		// If the link appears to be hashed already, don't bother
		if (strpos($qs, '||')) {
			self::$log[] = '<strong>Link appears to be signed already</strong>: '.htmlspecialchars($code[0]);
			return $fail;
		}

		// Stick an ampersand on the beginning of the querystring to make matching the first element a little easier
		$qs = '&'.urldecode($qs);

		// Get all the prefixes, codes, and name=value pairs
		preg_match_all('%(?P<amp>&(?:amp;)?)(?P<prefix>[a-z0-9]{1,3}:)?(?P<name>[^=]+)=(?P<value>[^&]+)%', $qs, $pairs, PREG_SET_ORDER);
		self::$log[] = 'Found the following pairs to sign:<pre>'.htmlspecialchars(print_r($pairs, true)).'</pre>';

		// Get all the "code" values, set the matches in $codes
		$codes = array();
		foreach ($pairs as $pair) {
			if ($pair['name'] == 'code') {
				$codes[$pair['prefix']] = $pair['value'];
			}
		}
		if ( ! count($codes)) {
			self::$log[] = '<strong style="color:#600;">No code found</strong> for the above link.';
			return $fail;
		}
		self::$log[] = '<strong style="color:orange;">CODES found:</strong> '.htmlspecialchars(print_r($codes, true));

		// Sign the name/value pairs
		foreach ($pairs as $pair) {
			// Skip the cart excludes
			if (in_array($pair['name'], self::$cart_excludes) || in_array($pair['prefix'], self::$cart_excludes_prefixes)) {
				self::$log[] = '<strong style="color:purple;">Skipping</strong> the reserved parameter or prefix "'.$pair['prefix'].$pair['name'].'" = '.$pair['value'];
				continue;
			}

			// Continue to sign the value and replace the name=value in the querystring with name=value||hash
			$value = self::fc_hash_value($codes[$pair['prefix']], $pair['name'], $pair['value'], 'value', FALSE, 'urlencode');
			$replacement = $pair['amp'].$pair['prefix'].urlencode($pair['name']).'='.$value;
			$qs = str_replace($pair[0], $replacement, $qs);
			self::$log[] = 'Signed <strong>'.$pair['name'].'</strong> = <strong>'.$pair['value'].'</strong> with '.$replacement.'.<br />Replacing: '.$pair[0].'<br />With... '.$replacement;
		}
		$qs = ltrim($qs, '&'); // Get rid of that leading ampersand we added earlier

		if ($output) {
			echo self::$cart_url.'?'.$qs;
		} else {
			return self::$cart_url.'?'.$qs;
		}
	}


	/**
	 * "Form Method": Generate HMAC SHA256 for form elements or individual <input />s
	 *
	 * @return string
	 **/
	public static function fc_hash_value($product_code, $option_name, $option_value = '', $method = 'name', $output = TRUE, $urlencode = false) {
		if (!$product_code || !$option_name) {
			return FALSE;
		}
		if ($option_value == '--OPEN--') {
			$hash = hash_hmac('sha256', $product_code.$option_name.$option_value, self::$secret);
			$value = ($urlencode) ? urlencode($option_name).'||'.$hash.'||open' : $option_name.'||'.$hash.'||open';
		} else {
			$hash = hash_hmac('sha256', $product_code.$option_name.$option_value, self::$secret);
			if ($method == 'name') {
				$value = ($urlencode) ? urlencode($option_name).'||'.$hash : $option_name.'||'.$hash;
			} else {
				$value = ($urlencode) ? urlencode($option_value).'||'.$hash : $option_value.'||'.$hash;
			}
		}

		if ($output) {
			echo $value;
		} else {
			return $value;
		}
	}

	/**
	 * Raw HTML Signing: Sign all links and form elements in a block of HTML
	 *
	 * Accepts a string of HTML and signs all links and forms.
	 * Requires link 'href' and form 'action' attributes to use 'https' and not 'http'.
	 * Requires a 'code' to be set in every form.
	 *
	 * @return string
	 **/
	public static function fc_hash_html($html) {
		// Initialize some counting
		$count['temp'] = 0; // temp counter
		$count['links'] = 0;
		$count['forms'] = 0;
		$count['inputs'] = 0;
		$count['lists'] = 0;
		$count['textareas'] = 0;

		// Find and sign all the links
		preg_match_all('%<a .*?href=[\'"]'.preg_quote(self::$cart_url).'(?:\.php)?\?(.+?)[\'"].*?>%i', $html, $querystrings);
		// print_r($querystrings);
		foreach ($querystrings[1] as $querystring) {
			// If it's already signed, skip it.
			if (preg_match('%&(?:amp;)?hash=%i', $querystring)) {
				continue;
			}
			$pattern = '%(href=[\'"])'.preg_quote(self::$cart_url, '%').'(?:\.php)?\?'.preg_quote($querystring, '%').'([\'"])%i';
			$signed = self::fc_hash_querystring($querystring, FALSE);
			$html = preg_replace($pattern, '$1'.$signed.'$2', $html, -1, $count['temp']);
			$count['links'] += $count['temp'];
		}
		unset($querystrings);

		// Find and sign all form values
		preg_match_all('%<form [^>]*?action=[\'"]'.preg_quote(self::$cart_url).'(?:\.php)?[\'"].*?>(.+?)</form>%is', $html, $forms);
		foreach ($forms[1] as $form) {
			$count['forms']++;
			self::$log[] = '<strong>Signing form</strong> with data: '.htmlspecialchars(substr($form, 0, 150)).'...';

			// Store the original form so we can replace it when we're done
			$form_original = $form;

			// Check for the "code" input, set the matches in $codes
			if (!preg_match_all('%<[^>]*?name=([\'"])([0-9]{1,3}:)?code\1[^>]*?>%i', $form, $codes, PREG_SET_ORDER)) {
				self::$log[] = '<strong style="color:#600;">No code found</strong> for the above form.';
				continue;
			}
			// For each code found, sign the appropriate inputs
			foreach ($codes as $code) {
				// If the form appears to be hashed already, don't bother
				if (strpos($code[0], '||')) {
					self::$log[] = '<strong>Form appears to be signed already</strong>: '.htmlspecialchars($code[0]);
					continue;
				}
				// Get the code and the prefix
				$prefix = (isset($code[2])) ? $code[2] : '';
				preg_match('%<[^>]*?value=([\'"])(.+?)\1[^>]*?>%i', $code[0], $code);
				$code = trim($code[2]);
				self::$log[] = '<strong>Prefix for '.htmlspecialchars($code).'</strong>: '.htmlspecialchars($prefix);
				if (!$code) { // If the code is empty, skip this form or specific prefixed elements
					continue;
				}

				// Sign all <input /> elements with matching prefix
				preg_match_all('%<input [^>]*?name=([\'"])'.preg_quote($prefix).'(?![0-9]{1,3})(?:.+?)\1[^>]*>%i', $form, $inputs);
				foreach ($inputs[0] as $input) {
					$count['inputs']++;
					// Test to make sure both name and value attributes are found
					if (preg_match('%name=([\'"])'.preg_quote($prefix).'(?![0-9]{1,3})(.+?)\1%i', $input, $name) > 0) {
						preg_match('%value=([\'"])(.*?)\1%i', $input, $value);
						$value = (count($value) > 0) ? $value : array('', '', '');
						self::$log[] = '<strong>INPUT:</strong> Code: <strong>'.$prefix.htmlspecialchars(preg_quote($name[2])).'</strong>';
						self::$log[] = '<strong>Replacement Pattern:</strong> ([\'"])'.$prefix.preg_quote($name[2]).'\1';
						$value[2] = ($value[2] == '') ? '--OPEN--' : $value[2];
						$input_signed = preg_replace('%([\'"])'.$prefix.preg_quote($name[2]).'\1%', '${1}'.$prefix.self::fc_hash_value($code, $name[2], $value[2], 'name', FALSE)."$1", $input);
						self::$log[] = '<strong>INPUT:</strong> Code: <strong>'.htmlspecialchars($prefix.$code).
						               '</strong> :: Name: <strong>'.htmlspecialchars($prefix.$name[2]).
						               '</strong> :: Value: <strong>'.htmlspecialchars($value[2]).
						               '</strong><br />Initial input: '.htmlspecialchars($input).
						               '<br />Signed: <span style="color:#060;">'.htmlspecialchars($input_signed).'</span>';
						$form = str_replace($input, $input_signed, $form);
					}
				}
				self::$log[] = '<strong>FORM after INPUTS:</strong> <pre>'.htmlspecialchars($form).'</pre>';

				// Sign all <option /> elements
				preg_match_all('%<select [^>]*name=([\'"])'.preg_quote($prefix).'(?![0-9]{1,3})(.+?)\1[^>]*>(.+?)</select>%is', $form, $lists, PREG_SET_ORDER);
				foreach ($lists as $list) {
					$count['lists']++;
					preg_match_all('%<option [^>]*value=([\'"])(.+?)\1[^>]*>(?:.*?)</option>%i', $list[0], $options, PREG_SET_ORDER);
					self::$log[] = '<strong>Options:</strong> <pre>'.htmlspecialchars(print_r($options, true)).'</pre>';
					foreach ($options as $option) {
						$option_signed = preg_replace(
							'%'.preg_quote($option[1]).preg_quote($option[2]).preg_quote($option[1]).'%',
							$option[1].self::fc_hash_value($code, $list[2], $option[2], 'value', FALSE).$option[1],
							$option[0]);
						$form = str_replace($option[0], $option_signed, $form);
						self::$log[] = '<strong>OPTION:</strong> Code: <strong>'.htmlspecialchars($prefix.$code).
						               '</strong> :: Name: <strong>'.htmlspecialchars($prefix.$list[2]).
						               '</strong> :: Value: <strong>'.htmlspecialchars($option[2]).
						               '</strong><br />Initial option: '.htmlspecialchars($option[0]).
						               '<br />Signed: <span style="color:#060;">'.htmlspecialchars($option_signed).'</span>';
					}
				}
				self::$log[] = '<strong>FORM after OPTIONS:</strong> <pre>'.htmlspecialchars($form).'</pre>';

				// Sign all <textarea /> elements
				preg_match_all('%<textarea [^>]*name=([\'"])'.preg_quote($prefix).'(?![0-9]{1,3})(.+?)\1[^>]*>(.*?)</textarea>%is', $form, $textareas, PREG_SET_ORDER);
				// echo "\n\nTextareas: ".print_r($textareas, true);
				foreach ($textareas as $textarea) {
					$count['textareas']++;
					// Tackle implied "--OPEN--" first, if textarea is empty
					$textarea[3] = ($textarea[3] == '') ? '--OPEN--' : $textarea[3];
					$textarea_signed = preg_replace('%([\'"])'.preg_quote($prefix.$textarea[2]).'\1%', "$1".self::fc_hash_value($code, $textarea[2], $textarea[3], 'name', FALSE)."$1", $textarea[0]);
					$form = str_replace($textarea[0], $textarea_signed, $form);
					self::$log[] = '<strong>TEXTAREA:</strong> Code: <strong>'.htmlspecialchars($prefix.$code).
					               '</strong> :: Name: <strong>'.htmlspecialchars($prefix.$textarea[2]).
					               '</strong> :: Value: <strong>'.htmlspecialchars($textarea[3]).
					               '</strong><br />Initial textarea: '.htmlspecialchars($textarea[0]).
					               '<br />Signed: <span style="color:#060;">'.htmlspecialchars($textarea_signed).'</span>';
				}
				self::$log[] = '<strong>FORM after TEXTAREAS:</strong> <pre>'.htmlspecialchars($form).'</pre>';

				// Exclude all <button> elements
				$form = preg_replace('%<button ([^>]*)name=([\'"])(.*?)\1([^>]*>.*?</button>)%i', "<button $1name=$2x:$3$4", $form);

			}
			// Replace the entire form
			self::$log[] = '<strong>FORM after ALL:</strong> <pre>'.htmlspecialchars($form).'</pre>'.'replacing <pre>'.htmlspecialchars($form_original).'</pre>';
			$html = str_replace($form_original, $form, $html);
			self::$log[] = '<strong>FORM end</strong><hr />';
		}

		// Return the signed output
		$output = '';
		if (self::$debug) {
			self::$log['Summary'] = $count['links'].' links signed. '.$count['forms'].' forms signed. '.$count['inputs'].' inputs signed. '.$count['lists'].' lists signed. '.$count['textareas'].' textareas signed.';
			$output .= '<h3>FoxyCart HMAC Debugging:</h3><ul>';
			foreach (self::$log as $name => $value) {
				$output .= '<li><strong>'.$name.':</strong> '.$value.'</li>';
			}
			$output .= '</ul><hr />';
		}
		return $output.$html;
	}

}