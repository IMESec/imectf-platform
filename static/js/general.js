$(function() {
  /*****************/
  /*  Semantic UI  */
  /*****************/

  $('.tasks-table').tablesort()
  $('.ui.dropdown').dropdown()
  $('.checkbox').checkbox('attach events', '.check.button', 'check');

  var dimmerSettings = { duration: { show: 100, hide: 100 }, inverted: true, useCSS: false };
  $('.ui.dimmer').dimmer(dimmerSettings);
  $('.ui.modal').modal({ dimmerSettings: dimmerSettings });


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
  /*   Utilities   */
  /*****************/
  var tagsToReplace = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;'
  };

  function replaceTag(tag) {
    return tagsToReplace[tag] || tag;
  }

  escapeHtml = function(str) {
    return str.replace(/[&<>]/g, replaceTag);
  }


  /*****************/
  /* Ajax Queries  */
  /*****************/
  $.ajaxSetup({
    method: 'POST',
    cache: false,
    contentType: false,
    processData: false,
  });

  ajaxQuery = function(url, data, success, error) {
    $('.task-loading').dimmer('show');
    $.ajax({ url: url, data: data })
      .always(function() { $('.task-loading').dimmer('hide'); })
      .done(function(res) {
        if (success)
          success(res);
      })
      .fail(function() {
        $('.task-loading').dimmer('hide');
        console.log('error');
        if (error)
          error();
      });
  };

  fetchTaskToForm = function(url, form, callback) {
    $('.task-loading').dimmer('show');
    $.ajax({ url: url })
      .always(function() { $('.task-loading').dimmer('hide'); })
      .done(function(res) {
        // TODO change server to return status and task, not only task
        $.each(res, function(name, v) {
          var elem = form.find('[name=task-'+name+']');
          if (elem.length > 0 && elem.attr('type') != "file")
            elem.val(v);
        });

        form.find('.task-category-dropdown').dropdown('set selected', res['category']);

        if (callback)
          callback();
      })
      .fail(function() {
        console.log('error');
      });
  };
});
