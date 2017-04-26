$(function() {
  /*****************/
  /*  Semantic UI  */
  /*****************/

  $('.tasks-table').tablesort()
  $('.ui.dropdown').dropdown()
  $('.checkbox').checkbox('attach events', '.check.button', 'check');


  /*****************/
  /* File Selector */
  /*****************/

  $(document).on('change', '.btn-file :file', function() {
    var input = $(this);

    if (navigator.appVersion.indexOf("MSIE") != -1) { // IE
      var label = input.val();

      input.trigger('fileselect', [ 1, label, 0 ]);
    } else {
      var label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
      var numFiles = input.get(0).files ? input.get(0).files.length : 1;
      var size = input.get(0).files[0].size;

      input.trigger('fileselect', [ numFiles, label, size ]);
    }
  });

  $('.btn-file :file').on('fileselect', function(event, numFiles, label, size) {
    $(this).attr('name', 'task-file'); // allow upload.
    $(this).parent().next('._attachmentName').val(label);
  });


  /*****************/
  /* Ajax Queries  */
  /*****************/
  $.ajaxSetup({
    method: 'POST',
    cache: false,
    contentType: false,
    processData: false,
  });

  ajaxQuery = function(url, data, callback) {
    $.ajax({
      url: url,
      data: data,
      success: function(res) {
        if (res['status'] === 'OK') {
          if (callback)
            callback(res);
        } else {
          console.log(res['message']);
        }
      }
    });
  };

  fetchTaskToForm = function(url, form) {
    $.ajax({
      url: url,
      success: function(res) {
        $.each(res, function(name, v) {
          var elem = form.find('[name=task-'+name+']');
          if (elem.length > 0 && elem.attr('type') != "file")
            elem.val(v);
        });

        form.find('.task-category-dropdown').dropdown('set selected', res['category']);
      },
      error: function() {
        console.log("error");
      }
    });
  };
});
