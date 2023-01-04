window.addEventListener('DOMContentLoaded', event => {
    // Simple-DataTables
    // https://github.com/fiduswriter/Simple-DataTables/wiki
    $(document).ready(function() {
        const scdg_param = document.getElementById('scdg_param');
        if (scdg_param) {
            new simpleDatatables.DataTable(scdg_param);
        }

        const scdg_res = document.getElementById('dataTable');
        if (scdg_res) {
            new simpleDatatables.DataTable(scdg_res);
        }

        const class_param = document.getElementById('class_param');
        if (class_param) {
            new simpleDatatables.DataTable(class_param);
        }

        const class_res = document.getElementById('class_res');
        if (class_res) {
            new simpleDatatables.DataTable(class_res);
        }
    });
});
