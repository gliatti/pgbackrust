//! Shared list-pagination driver for object-store backends.
//!
//! S3, Azure and GCS all paginate their directory listings with a
//! continuation token (S3 `NextContinuationToken`, Azure `NextMarker`, GCS
//! `nextPageToken`): a single `list` call returns at most a page of entries
//! plus an opaque token to fetch the next page. Each backend used to open-code
//! the "loop until the token runs out" walk, which is where an unbounded-loop
//! or a dropped-page bug slips in. [`paginate`] centralises that walk once so
//! every backend inherits the same termination and anti-loop guarantees.
//!
//! The accumulated entries are returned **unsorted** — callers already sort the
//! materialised `Vec<StorageInfo>` before handing it back through the
//! [`crate::Storage::list`] contract, so sorting here would be redundant work.

use crate::StorageError;

/// Drive a token-paginated listing to completion, concatenating every page.
///
/// `fetch` is called with the current continuation marker (`None` on the first
/// call, then the token returned by the previous page) and must return the
/// page's entries together with the token for the *next* page (`None` once the
/// listing is exhausted).
///
/// Termination:
///
/// - stops as soon as `fetch` returns a `None` next-token (normal end of list);
/// - **anti-loop guard**: if `fetch` returns a next-token *equal to the marker
///   just used* the listing is not making progress (a misbehaving or buggy
///   endpoint would otherwise spin forever), so the walk stops after folding in
///   that page rather than looping indefinitely.
///
/// The returned `Vec` is the concatenation of every page in fetch order and is
/// **not** sorted — the caller owns final ordering.
///
/// # Errors
///
/// Propagates the first [`StorageError`] returned by `fetch`; the pages
/// accumulated so far are discarded.
pub fn paginate<T>(
    mut fetch: impl FnMut(Option<&str>) -> Result<(Vec<T>, Option<String>), StorageError>,
) -> Result<Vec<T>, StorageError> {
    let mut out: Vec<T> = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let (page, next) = fetch(marker.as_deref())?;
        out.extend(page);

        match next {
            // End of listing.
            None => break,
            // Anti-loop guard: the endpoint handed back the very marker we just
            // used, so the next call would fetch the same page again forever.
            // Fold in this page (already done above) and stop.
            Some(ref token) if Some(token.as_str()) == marker.as_deref() => break,
            Some(token) => marker = Some(token),
        }
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn paginate_walks_multiple_pages_in_order() {
        // Three pages: markers None -> "p2" -> "p3" -> end.
        let pages: RefCell<Vec<(Vec<u32>, Option<String>)>> = RefCell::new(vec![
            (vec![1, 2], Some("p2".to_owned())),
            (vec![3, 4], Some("p3".to_owned())),
            (vec![5], None),
        ]);
        // Record the markers we were called with, to prove progression.
        let seen: RefCell<Vec<Option<String>>> = RefCell::new(Vec::new());

        let out = paginate(|marker| {
            seen.borrow_mut().push(marker.map(str::to_owned));
            Ok(pages.borrow_mut().remove(0))
        })
        .unwrap();

        assert_eq!(out, vec![1, 2, 3, 4, 5]);
        assert_eq!(
            *seen.borrow(),
            vec![None, Some("p2".to_owned()), Some("p3".to_owned())],
            "each page must be fetched with the previous page's token"
        );
    }

    #[test]
    fn paginate_stops_on_none_token_single_page() {
        let out = paginate(|_marker| Ok((vec![42u8], None))).unwrap();
        assert_eq!(out, vec![42]);
    }

    #[test]
    fn paginate_stops_when_token_does_not_advance() {
        // The endpoint keeps returning the same non-None token forever. Without
        // the anti-loop guard this would spin indefinitely; with it we fold in
        // exactly the pages fetched until the token repeats the marker we used.
        let calls = RefCell::new(0u32);

        let out = paginate(|marker| {
            *calls.borrow_mut() += 1;
            // First call: marker None, hand back token "stuck".
            // Second call: marker "stuck", hand back token "stuck" again ->
            //   equals the marker just used -> guard fires, stop.
            if marker.is_none() {
                Ok((vec![1u32], Some("stuck".to_owned())))
            } else {
                Ok((vec![2u32], Some("stuck".to_owned())))
            }
        })
        .unwrap();

        assert_eq!(out, vec![1, 2]);
        assert_eq!(*calls.borrow(), 2, "must stop after the non-advancing token repeats");
    }
}
