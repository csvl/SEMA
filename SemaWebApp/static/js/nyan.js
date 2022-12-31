/**
 * Created by JetBrains PhpStorm.
 * User: bjost
 * Date: 7/13/11
 * Time: 10:48 AM
 * To change this template use File | Settings | File Templates.
 */

function nyanCat(width) {
	if(width.length > 0) {
		this.width = parseInt(width);
	} else {
		this.width = 100;
	}
	
	progressContainer = document.getElementById('rainbowContainer');
	console.log(progressContainer.style.width);
	progressContainer.style.width = 75 + "%";

	this.setPercent = function(percent) {
		this.percent = parseInt(percent);

        this.pixels = (this.percent / 100) * progressContainer.offsetWidth

		progress = document.getElementById('rainbow');
		cat = document.getElementById('nyanCat');

		progress.style.width = this.pixels.toString() + "px";

		catProgress = this.pixels;

		cat.style.left = catProgress.toString() + "px";
	} //percent
} //nyanCat
