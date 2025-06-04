<?php
/*
Plugin Name: WooCommerce Rest API
Description: Custom REST API endpoints for WooCommerce cart operations.
Version: 1.0
Author: Siphamandla Mbokazi
*/

// Register custom REST API endpoints
function register_custom_cart_endpoints() 
{
    // Include necessary WooCommerce files
    include_once WC_ABSPATH . 'includes/wc-cart-functions.php';
   
    include_once WC_ABSPATH . 'includes/class-wc-cart.php';

    // Ensure cart object is loaded
    if ( is_null( WC()->cart ) ) {
        wc_load_cart();

    }


   register_rest_route('customauth/v1', '/register', array(
        'methods' => 'POST',
        'callback' => 'custom_user_registration',
        'permission_callback' => 'allow_route_access',
    ));

    register_rest_route('customauth/v1', '/login', array(
        'methods' => 'POST',
        'callback' => 'custom_user_login',
        'permission_callback' => 'allow_route_access',
    ));


    register_rest_route('customauth/v1', '/verify-token', array(
        'methods' => 'POST',
        'callback' => 'custom_verify_token',
        'permission_callback' => 'allow_route_access',
    ));

    register_rest_route('customauth/v1', '/reset-password', array(
        'methods' => 'POST',
        'callback' => 'custom_password_reset',
        'permission_callback' => 'allow_route_access',
    ));

    register_rest_route('customauth/v1', '/change-password', array(
        'methods' => 'POST',
        'callback' => 'custom_change_password',
        'permission_callback' =>'allow_route_access',
    ));


    register_rest_route('customcart/v1', '/add-to-cart', array(
        'methods' => 'POST',
        'callback' => 'custom_add_to_cart',
        'permission_callback' => 'allow_route_access'
    ));


    register_rest_route('sellinglocations/v1', '/allowed-countries', array(
        'methods' => 'get',
        'callback' => 'get_allowed_countries',
        'permission_callback' => 'allow_route_access'
    ));
    register_rest_route('sellinglocations/v1', '/allowed-states', array(
        'methods' => 'get',
        'callback' => 'get_allowed_states',
        'permission_callback' => 'allow_route_access'
    ));


    register_rest_route('shipping/v1', '/shipping-methods', array(
        'methods' => 'get',
        'callback' => 'get_shipping_methods',
        'permission_callback' => 'allow_route_access'
    ));

    register_rest_route( 'hero-banners/v1', '/page/(?P<slug>[\w-]+)', array(
        'methods'  => 'GET',
        'callback' => 'custom_get_hero_banner_by_slug',
    ));
}


add_action('rest_api_init', 'register_custom_cart_endpoints');



function generate_and_store_keys()
{
    $token_key = bin2hex(random_bytes(16)); // Generate a random token key
    $api_key = bin2hex(random_bytes(16)); // Generate a random API key

    // Store keys in WordPress options
    update_option('woorest_token_key', $token_key);
    update_option('woorest_api_key', $api_key);
}

register_activation_hook(__FILE__, 'generate_and_store_keys');

function allow_route_access($request) 
{
    //temporarily return
    return true;

    $token_key = get_option('woorest_token_key');
    $api_key = get_option('woorest_api_key');

    $sent_token_key = $request->get_header('X-Token-Key');
    $sent_api_key = $request->get_header('X-API-Key');

    if ($token_key === $sent_token_key && $api_key === $sent_api_key) {
        return true; // Allow access
    } else {
        return false; // Deny access
    }
}


/**
 * Register a new user to WordPress with role as 'customer' and include billing and shipping info along with other customer details
 *
 * @param WP_REST_Request $request Request data containing Username, Password, Email, billing details, shipping details, and additional customer details
 *
 * @return WP_REST_Response Response message along with status code
 */
function custom_user_registration(WP_REST_Request $request) : WP_REST_Response
{
    $username = sanitize_text_field($request->get_param('username'));
    $email = sanitize_email($request->get_param('email'));
    $password = $request->get_param('password');

    // Additional customer details
    $first_name = sanitize_text_field($request->get_param('first_name'));
    $last_name = sanitize_text_field($request->get_param('last_name'));
    $address = sanitize_textarea_field($request->get_param('address'));
    $phone_number = sanitize_text_field($request->get_param('phone_number'));



    if (username_exists($username)) {
        return new WP_REST_Response('Conflict: The username already exists', 409);
    }

    if (email_exists($email)) {
        return new WP_REST_Response('Conflict: The email address already exists', 409);
    }


    $customer = new WC_Customer();


    $customer->set_username( $username );
    $customer->set_email( $email );
    $customer->set_password( $password );
    $customer->set_first_name( $first_name );
    $customer->set_last_name( $last_name );

   //$customer->set_address( $address );
   //$customer->set_phone( $phone );

   //return new WP_REST_Response('Email already exists.', 200);



    // Billing information
    $billing_first_name = sanitize_text_field($request->get_param('billing_first_name'));
    $billing_last_name = sanitize_text_field($request->get_param('billing_last_name'));
    $billing_email = sanitize_text_field($request->get_param('billing_email'));
    $billing_phone = sanitize_text_field($request->get_param('billing_phone'));

    $billing_address = sanitize_textarea_field($request->get_param('billing_address'));
    $billing_country = sanitize_text_field($request->get_param('billing_country'));
    $billing_state = sanitize_text_field($request->get_param('billing_state'));
    $billing_zip = sanitize_text_field($request->get_param('billing_zip'));
    $billing_city = sanitize_text_field($request->get_param('billing_city'));


    $customer->set_billing_first_name( $billing_first_name );
    $customer->set_billing_last_name( $billing_last_name );
    $customer->set_billing_email( $billing_email );
    $customer->set_billing_phone( $billing_phone );

    $customer->set_billing_address( $billing_address );
    $customer->set_billing_address_to_base();
    $customer->set_billing_country( $billing_country );
    $customer->set_billing_state( $billing_state );
    $customer->set_billing_postcode( $billing_zip );
    $customer->set_billing_city( $billing_city );


    // shipping information
    $shipping_first_name = sanitize_text_field($request->get_param('shipping_first_name'));
    $shipping_last_name = sanitize_text_field($request->get_param('shipping_last_name'));
    $shipping_email = sanitize_text_field($request->get_param('shipping_email'));
    $shipping_phone = sanitize_text_field($request->get_param('shipping_phone'));

    $shipping_address = sanitize_textarea_field($request->get_param('shipping_address'));
    $shipping_country = sanitize_text_field($request->get_param('shipping_country'));
    $shipping_state = sanitize_text_field($request->get_param('shipping_state'));
    $shipping_zip = sanitize_text_field($request->get_param('shipping_zip'));
    $shipping_city = sanitize_text_field($request->get_param('shipping_city'));



    $customer->set_shipping_first_name( $shipping_first_name );
    $customer->set_shipping_last_name( $shipping_last_name );
   // $customer->set_shipping_email( $shipping_email );

    $customer->set_shipping_phone( $shipping_phone );

    
    $customer->set_shipping_address( $shipping_address );
    $customer->set_shipping_address_to_base();
    $customer->set_shipping_country( $shipping_country );
    $customer->set_shipping_state( $shipping_state );
    $customer->set_shipping_postcode( $shipping_zip );
    $customer->set_shipping_city( $shipping_city );



    //save all at once
    $customer->save();

    // Send confirmation email
    $to = $email;
    $subject = 'Confirmation';
    $body = 'Thanks for registering with us.';
    $headers = array('Content-Type: text/html; charset=UTF-8');

    wp_mail($to, $subject, $body, $headers);

    return new WP_REST_Response('User registered successfully.', 201);
}



/**
 * Log user in
 * 
 * if logged successful create and return a token
 * 
 * @param POST $request with Username, Password and Email
 * 
 * @return : WP_REST_Response with a jwt auth token
 **/

function custom_user_login($request) : WP_REST_Response 
{
  $username = sanitize_text_field($request->get_param('username'));
  $password = $request->get_param('password');

  $user = wp_authenticate($username, $password);

  if (is_wp_error($user)) {
    return new WP_REST_Response(  'Invalid username or password', 401 );
  }

  // Generate and return JWT token
  //$token = generate_custom_token($user->ID);

  return new WP_REST_Response(  $user, 201 );
}



/**
 * Generate a 2hour lasting token
 * 
 * @param user Id
 * 
 * @return : base64 encoded token
 **/
function generate_custom_token( $user_id ) : string
{
    $secret_key = 'eyJpYXQiOjE3MTEwMjUyMDYsImV4cCI6MTcxMTAzMjQwNiwiZGF0YSI6eyJ1c2VyX2lkIjo1fX0='; // Replace with your secret key
    $issued_at = time();
    $expiration_time = $issued_at + ( 2 * 60 * 60); // Token valid for 2 days

    // Create token payload
    $token_data = array(
        'iat' => $issued_at,
        'exp' => $expiration_time,
        'data' => array(
            'user_id' => $user_id,
            // Add more user data as needed
        ),
    );

    // Encode token
    $jwt = base64_encode(json_encode($token_data)); // Simple base64 encoding for demonstration

    return $jwt;
}



// Callback function for token verification endpoint
function custom_verify_token($request) 
{
    $token = $request->get_param('token'); // Token sent in the request


    if (!$token) {
        
        return new WP_REST_Response(  'Token is required.', 401 );
    }


    $token_data = verify_custom_token($token);


    if ($token_data) {
        return new WP_REST_Response(  $token_data, 201 );
    } else {
        return new WP_REST_Response(  'Invalid or expired token.', 401 );
    }
}


// Verify and decode custom token
function verify_custom_token($token) 
{
    $decoded_token = json_decode(base64_decode($token), true);

    if ($decoded_token) {
        // Check token expiration
        if (isset($decoded_token['exp']) && time() <= $decoded_token['exp']) {
            return $decoded_token['data']; // Token is valid, return token data
        }
    }

    return false; // Token is invalid or expired
}



/**
* Custom callback function for adding items to WooCommerce cart.
*
* @param WP_REST_Request $request The REST request object.
* @return WP_REST_Response The REST response object.
*/
function custom_add_to_cart( WP_REST_Request $request ): WP_REST_Response 
{
    // Get JSON data from request body
    $product = $request->get_json_params();
   
    // Ensure request is valid 
    if ( empty( $product ) || ! is_array( $product ) || empty( $product['product'] ) ) 
        return new WP_REST_Response( 'Invalid JSON data', 401 );

    if( $product["product"] === "RESET_CART" ){
        WC()->cart->empty_cart();
        return new WP_REST_Response( custom_get_cart_items(), 201 );
    }

    foreach ( $product['product'] as $item ) {
        
        $product_id = isset( $item['product_id'] ) ? absint( $item['product_id'] ) : 0;
 
        $quantity = isset( $item['quantity'] ) ? intval( $item['quantity'] ) : 1;
        
        // Check if product exists
        if ( wc_get_product( $product_id ) ) 
            WC()->cart->add_to_cart( $product_id, $quantity );
        else   
            return new WP_REST_Response( "Product ID $product_id  does not exist.", 401 );
        
    }

    $cart_contents = custom_get_cart_items();

    if( is_array($cart_contents) && count( $cart_contents ) > 0 ) 
        return new WP_REST_Response( $cart_contents, 201 );
    
    return new WP_REST_Response( '', 205 );
}


/**
 * Retrieves cart items with specified properties.
 * 
 * @return Array of cart items with product_id, name, price, and quantity.
 */
function custom_get_cart_items(): array
{
    // Get updated cart contents
    $cart_contents = WC()->cart->get_cart();
    $cart = [];
    $cart_items = [];
    $cart_totals = [];

    if ( !empty($cart_contents) ) {
        // Loop through cart items
        foreach ($cart_contents as $cart_item_key => $cart_item) {
            // Extract necessary information from cart item
            $product_id = $cart_item['product_id'];
            $product_name = $cart_item['data']->get_name();
            $product_price = $cart_item['data']->get_price();
            $product_quantity = $cart_item['quantity'];
            $product_image = wp_get_attachment_image_src(get_post_thumbnail_id($product_id), 'single-post-thumbnail')[0];

            // Build cart item array
            $cart_items[] = [
                'product_id' => $product_id,
                'name' => $product_name,
                'price' => $product_price,
                'quantity' => $product_quantity,
                'image' => $product_image, 
                'currency' => html_entity_decode( get_woocommerce_currency_symbol() )


            ];
        }

        $cart['cart_items'] = $cart_items;


        // Calculate cart subtotal and total
        $cart_subtotal = WC()->cart->subtotal;
        $cart_total = WC()->cart->total;
        $cart_totals[]['cart_subtotal'] = wc_price( $cart_subtotal );
        $cart_totals[]['cart_total'] = wc_price( $cart_total );
        $cart['totals'] = $cart_totals;
    }

    return $cart;
}


/** 
 * Get email for password reset, check if it exists, generate a unique token, update the token
 * , add url params (user id, token appended ) to the client password url and then run send it to the user via email
 * 
 * @param $request with email
 * @return WP_REST_Response with user token a
 * */
// Callback function for handling password reset request
function custom_password_reset($request) 
{
    $parameters = $request->get_json_params();

    // Check if email is provided
    if (empty($parameters['email'])) {
        return new WP_REST_Response( 'Email is required', 401 );
    }

    // Check if user with provided email exists
    $user = get_user_by('email', $parameters['email']);
    if (!$user) {
        return new WP_REST_Response('User with this email does not exist', 404 );
    }

    // Generate a unique token (for simplicity, we'll generate a random string here)
    $reset_token = wp_generate_password(20, false);

    // Save the token to user meta
    update_user_meta($user->ID, 'reset_password_token', $reset_token);

    // Construct reset link
    $base_url = 'http://localhost:3000/change-password'; // Update with your Next.js app URL
    $reset_link = add_query_arg(array(
        'user_id' => $user->ID,
        'reset_token' => $reset_token,
    ), $base_url);

    // Return token, user ID, and reset link
    return new WP_REST_Response(array(
        'user_id' => $user->ID,
        'reset_token' => $reset_token,
        'reset_link' => $reset_link,
    ), 201 );
}


function custom_change_password($request) 
{
    $parameters = $request->get_json_params();

    // Check if user_id, reset_token, and new_password are provided
    if (empty($parameters['user_id']) && empty($parameters['reset_token']) && empty($parameters['new_password'])) {
        return new WP_REST_Response('User ID, reset token, and new password are required', 401 );
    }

    // Verify reset token and user ID (custom logic based on your token storage and validation)
    $user_id = intval($parameters['user_id']);
    $reset_token = sanitize_text_field($parameters['reset_token']);
    
    // Check if the reset token matches the stored token for the user
    $stored_token = get_user_meta($user_id, 'reset_password_token', true);
    if ($reset_token !== $stored_token) {
        return new WP_REST_Response('Invalid reset token', 401);
    }

    // Update user's password
    $user = get_user_by('id', $user_id);
    if (!$user) {
        return new WP_REST_Response('User not found', 404);
    }

    wp_set_password($parameters['new_password'], $user_id);

    // Remove/reset the reset token after password update (optional)
    delete_user_meta($user_id, 'reset_password_token');

    // Return success response
    return new WP_REST_Response('Password updated successfully', 201 );
}




function get_allowed_countries($request) : WP_REST_Response
{
    $locations = [];
    
    // Get allowed countries
    $allowed_countries = WC()->countries->get_allowed_countries();
    
    // Loop through allowed countries
    foreach ($allowed_countries as $country_code => $country_name) {

        $locations[] = [
            'country_name' =>$country_name,
            'country_code'=>$country_code,
        ];
        
    }

    return new WP_REST_Response( $locations, 201 );
    
}

function get_allowed_states($request) : WP_REST_Response
{

  $params = $request->get_query_params(); // Retrieve GET parameters
  
  // Process parameters and data
  $country_code = isset( $params['country_code'] ) ? sanitize_text_field( $params['country_code'] ) : null;

   if( $country_code === null )
        return new WP_REST_Response( 'Country code is mandetory', 401 );


    
    // Get states for each country
    $states = WC()->countries->get_states($country_code);

    // Check if states exist
    if ( empty($states) ) 
        return new WP_REST_Response( 'No states found', 404 );

    $transformed_states = [];

    foreach ($states as $state_code => $state_name) {
        $transformed_states[] = [
            'state_name' => $state_name,
            'state_code' => $state_code
        ];
    }

    return new WP_REST_Response( $transformed_states, 201 );
    
}


// Callback function to retrieve shipping methods
function get_shipping_methods( $data ) {
    // Initialize an empty array to store shipping methods
    $shipping_methods = array();

    // Query shipping zones
    $zones = WC_Shipping_Zones::get_zones();

    // Loop through each shipping zone
    foreach ( $zones as $zone ) {
        // Get shipping methods for the zone
        $methods = $zone['shipping_methods'];

        // Loop through each method
        foreach ( $methods as $method ) {
            // Get the method ID and cost
            $method_id = $method->get_instance_id();
            $method_cost = $method->cost;

            // Build an array with method ID and cost
            $shipping_methods[] = array(
                'id' => $method_id,
                'title' => $method->title,
                'cost' => $method_cost,
            );
        }
    }

    return new WP_REST_Response( $shipping_methods, 201 );
}



function custom_register_hero_banner_post_type() 
{
    $labels = array(
        'name'               => __( 'Hero Banners', 'text-domain' ),
        'singular_name'      => __( 'Hero Banner', 'text-domain' ),
        'add_new'            => __( 'Add New Hero Banner', 'text-domain' ),
        'add_new_item'       => __( 'Add New Hero Banner', 'text-domain' ),
        'edit_item'          => __( 'Edit Hero Banner', 'text-domain' ),
        'new_item'           => __( 'New Hero Banner', 'text-domain' ),
        'view_item'          => __( 'View Hero Banner', 'text-domain' ),
        'search_items'       => __( 'Search Hero Banners', 'text-domain' ),
        'not_found'          => __( 'No hero banners found', 'text-domain' ),
        'not_found_in_trash' => __( 'No hero banners found in Trash', 'text-domain' ),
        'menu_name'          => __( 'Hero Banners', 'text-domain' ),
    );

    $args = array(
        'labels'              => $labels,
        'public'              => true,
        'show_in_rest'        => true, // Enable REST API support
        'supports'            => array( 'title', 'editor', 'thumbnail' ), // Add additional fields as needed
        'rewrite'             => array( 'slug' => 'hero-banner' ),
        'capability_type'     => 'post',
        'has_archive'         => false,
        'menu_icon'           => 'dashicons-format-image', // Choose an appropriate icon
    );

    register_post_type( 'hero_banner', $args );
}


function custom_get_hero_banner_by_slug( $data ) 
{
    $args = array(
        'post_type' => 'hero_banner',
        'name' => $data['slug'],
        'posts_per_page' => 1,
    );

    $query = new WP_Query( $args );
    $banner_data = [];
    if ( $query->have_posts() ) {
        $post = $query->posts[0];
        $banner_data = array(
            'title' => get_the_title( $post ),
            'description' => get_the_content( $post ),
            'image_url' => get_the_post_thumbnail_url( $post, 'full' ),
        );
        return $banner_data;
    } else {
        return new WP_REST_Response( 'Hero banner not found', 404 );
    }

    return new WP_REST_Response( $banner_data, 201 );
}


add_action( 'init', 'custom_register_hero_banner_post_type' );
