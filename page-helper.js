function PageHelper() {
  return {
    prefillPageData: function () {
      try {
        var pageData = sessionStorage.getItem('currentPage');
        const currentUser = JSON.parse(sessionStorage.getItem('currentUser') || '{}');
        var customUIPageData = null;
        if (interconnectJourney) {
          customUIPageData = currentUser?.data?.previousRecords ?? {};
        }
        if (pageData) {
          pageData = JSON.parse(pageData);
          if (pageData.uiConfig?.[0]?.customUIPageData && Object.keys(pageData.uiConfig[0].customUIPageData).length > 0) {
            customUIPageData = pageData.uiConfig[0].customUIPageData;
          }
        }

        function findValueByKeyName(keyName) {
          return customUIPageData?.[keyName] || null;
        }

        $('input[type="text"],input[type="email"],input[type="number"]').each(function () {
          var name = $(this).attr('name');
          if (!name) {
            name = $(this).attr('goid');
          }
          if (name) {
            name = name.trim();
            var value = findValueByKeyName(name);
            if (value) {
              $(this).val(value);
            }
          }
        });
        $('select').each(function () {
          var name = $(this).attr('name') || $(this).attr('goid') || '';
          name = name.trim();
          if (name) {
            var value = findValueByKeyName(name);
            if (value) {
              $(this).val(value).trigger('change');
            }
          }
        });
        $('.btn_group').each(function () {
          var name = $(this).children().first().attr('name');
          if (name) {
            name = name.trim();
            var value = findValueByKeyName(name);
            if (value) {
              $(this)
                .find('[name="' + name + '"]')
                .removeClass('active');
              $(this)
                .find('[name="' + name + '"]')
                .each(function () {
                  if ($(this).text() === value) {
                    $(this).addClass('active').trigger('click');
                  }
                });
            }
          }
        });
        $('input[type="radio"]').each(function () {
          var name = $(this).attr('name');
          if (!name) {
            name = $(this).attr('goid');
          }
          if (name) {
            name = name.trim();
            var value = findValueByKeyName(name);
            if (value === $(this).val()) {
              $(this).trigger('click');
            }
          }
        });
      } catch (e) {
        console.log(e);
      }
    }
  }
}