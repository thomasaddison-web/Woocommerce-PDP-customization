<?php
add_shortcode( 'series_information', 'display_series_information' );
function display_series_information($atts){
	if ( get_post_type( $post ) === 'product' && ! is_a($product, 'WC_Product') ) {
	    $product = wc_get_product( get_the_id() ); // Get the WC_Product Object
	}

	$product_attributes = $product->get_attributes(); // Get the product attributes

	// Output
	$manufacturer_id = $product_attributes['pa_series-name']['options']['0']; // returns the ID of the term
	$manufacturer_name = get_term( $manufacturer_id )->description; // gets the term name of the term from the ID
	$content = '<p class="attribute-label">'.$manufacturer_name.'</p>'; // display the actual term name

	return $content;
}

add_shortcode( 'see_inside', 'display_see_inside' );
function display_see_inside($atts){
	if ( get_post_type( $post ) === 'product' && ! is_a($product, 'WC_Product') ) {
	    $product = wc_get_product( get_the_id() ); // Get the WC_Product Object
	}

	$product_data = get_post_meta( get_the_id());
	$first_link = explode("https:",$product_data['ef3-pdf-book-preview'][0])[1];
	$second_link = explode(".pdf",$first_link)[0];
	$last_link = 'https:'.$second_link.'.pdf';
	$content = '<div class="book-preview"><a data-lity href="https://flowpaper.com/flipbook/?pdf='.$last_link.'?wp-hosted=1&title=see-inside&header=&theme=&singlepage=&thumbs=1&modified=240501301">See Inside</a></div>'; // display the actual term name

	return $content;
}

add_shortcode( 'cross_sells', 'display_cross_sells' );
function display_cross_sells($atts){
	if ( get_post_type( $post ) === 'product' && ! is_a($product, 'WC_Product') ) {
	    $product = wc_get_product( get_the_id() ); // Get the WC_Product Object
	}

    $content = '<ul>';
	$cross_sell_ids = $product->get_cross_sell_ids();
	foreach($cross_sell_ids as $id):
	    $c_product = wc_get_product( $id );
	    $content .= '<li><a href="' .$c_product->get_permalink(). '">'. $c_product->get_title().'</a></li>';
	endforeach;
	
	$content .= '</ul>';

	return $content;
}
