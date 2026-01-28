/******************************************************************************
 * CafeADVWorker Changes
 * 
 * This file shows the modifications needed to CafeADVWorker to support
 * initialization with pre-loaded CSV data.
 * 
 * ADD the following to your existing CafeADVWorker class:
 *   1. New constructor declaration in header
 *   2. New constructor implementation in cpp
 * 
 *****************************************************************************/

// =============================================================================
// ADD TO HEADER (CafeADVWorker.h) - in public section
// =============================================================================

public:
    /**************************************************************************
     * Constructor with pre-loaded data (CSV mode)
     * 
     * Creates a worker that starts with data already populated.
     * Skips initial DB query but still registers all listeners for updates.
     * 
     * @param specification         ADV specification
     * @param mds                   Message delivery service  
     * @param staticDataSource      Static data source
     * @param timeManager           Time manager
     * @param asyncDbPool           Async DB pool (for later updates)
     * @param flog                  Logger
     * @param initialData           Pre-loaded ADV data from CSV
     * @param initialDate           Date the data is for
     * @param specialDayMultiplier  Special day multiplier (optional)
     **************************************************************************/
    CafeADVWorker(
        const ADVSpecification&               specification,
        MessageDeliveryService*               mds,
        staticdata::InstrumentStaticSource*   staticDataSource,
        TimeManager*                          timeManager,
        std::shared_ptr<db::AsyncDbPool>      asyncDbPool,
        FLog                                  flog,
        const ADVData&                        initialData,
        const Date&                           initialDate,
        std::optional<double>                 specialDayMultiplier);


// =============================================================================
// ADD TO IMPLEMENTATION (CafeADVWorker.cpp)
// =============================================================================

/******************************************************************************
 * Constructor with pre-loaded data (CSV mode)
 * 
 * Same as original constructor BUT:
 *   - Sets _data immediately from initialData
 *   - Sets condition to LIVE immediately
 *   - Skips the initial fetch() call
 *   - Still registers listeners (onBing, onUpdate work normally)
 *****************************************************************************/
CafeADVWorker::CafeADVWorker(
    const ADVSpecification&               specification,
    MessageDeliveryService*               mds,
    staticdata::InstrumentStaticSource*   staticDataSource,
    TimeManager*                          timeManager,
    std::shared_ptr<db::AsyncDbPool>      asyncDbPool,
    FLog                                  flog,
    const ADVData&                        initialData,
    const Date&                           initialDate,
    std::optional<double>                 specialDayMultiplier)
    : MessageRecipient(mds)
    , _specification(specification)
    , _staticDataSource(staticDataSource)
    , _timeManager(timeManager)
    , _asyncDbPool(asyncDbPool)
    , _flog(FLog(parent: flog, tag: StringStr() << "CADV/"
          << sft::format(symbol: specification._instrument)
          << "/"))
{
    // Same date/time logic as original constructor
    std::string dateTimeStr;
    std::string dateStr;
    if (!_specification._dateTime.isNull()) {
        dateTimeStr = StringStr() << _specification._dateTime << "/";
    }
    if (!_specification._date.isNull()) {
        dateStr = StringStr() << _specification._date << "/";
    }
    
    // Same logging setup
    _flog = FLog(parent: flog, tag: StringStr() << "CADV/"
          << sft::format(symbol: specification._instrument)
          << "//"
          << dateStr
          << dateTimeStr);
    
    // Pre-populate data from CSV (DIFFERENT from original)
    _data = initialData;
    _date = initialDate;
    _asOfDate = initialDate;
    
    // Register for static data updates (SAME as original)
    staticdata::InstrumentStaticSpecification instSpec
        (instrument: _specification._instrument,
         includeListing: staticdata::RequestListing::DO_NOT_FETCH,
         includeTickRule: staticdata::RequestTickRule::DO_NOT_FETCH,
         includeCalendar: staticdata::RequestCalendar::FETCH,
         includeSecurity: staticdata::RequestSecurity::DO_NOT_FETCH,
         includeMarket: staticdata::RequestMarket::DO_NOT_FETCH,
         includeRegulatoryData: staticdata::RequestRegulatoryData::DO_NOT_FETCH,
         includeAutotradeableFlag: staticdata::RequestAutotradeableFlag::DO_NOT_FETCH,
         includeRestrictionCodes: staticdata::RequestRestrictionCodes::DO_NOT_FETCH,
         includeUnderlyingListing: staticdata::RequestUnderlyingListing::DO_NOT_FETCH,
         includeUnderlyingSecurity: staticdata::RequestUnderlyingSecurity::DO_NOT_FETCH,
         fungibleDataType: staticdata::FungibilityType::FREE,
         includeRegionalPrimary: staticdata::RequestRegionalPrimary::FETCH,
         includeGroups: staticdata::RequestGroups::DO_NOT_FETCH);
    _staticDataSource->get(identifier: instSpec, &dynamic: _staticData);
    _staticData.registerListenerWithSnapshot(listener: this);
    VOLTASSERT(!_staticData.isNull());
    
    // Set as LIVE immediately with CSV data (DIFFERENT from original)
    setIfChanged(
        description: ADVDescription(
            instrument: _specification._instrument,
            period: _dayCount,
            averageType: _specification._averageType.get(defaultValue: ADVType::MEDIAN),
            scope: _specification._scope,
            adjusted: false,
            source: "CAFEADV_CSV",
            date: _date,
            dateTime: _specification._dateTime,
            realisedVolumeHistory: analysis::RealisedVolumes(),
            exceptionDates: std::vector<volt::Date>(),
            specialDayMultiplier: specialDayMultiplier),
        data: _data,
        errorList: ADVError(),
        condition: Condition::LIVE);
    
    FLOG_DEBUG(_flog, StringStr() << "Initialized from CSV, condition=LIVE");
    
    // Still call bing() - so onBing() callback will work for future updates
    bing();
}


// =============================================================================
// NOTES
// =============================================================================
// 
// Key differences from original constructor:
//
// 1. ORIGINAL constructor:
//    - Initializes _data to NAN values
//    - Sets condition to INITIALISING
//    - Calls fetch() which triggers async DB query
//    - onTransactionCompleted() eventually sets condition to LIVE
//
// 2. NEW constructor (CSV mode):
//    - Sets _data directly from initialData parameter
//    - Sets condition to LIVE immediately via setIfChanged()
//    - Does NOT call fetch()
//    - Still registers listeners, still calls bing()
//
// Both constructors:
//    - Register for static data updates (_staticData.registerListenerWithSnapshot)
//    - Call bing() at the end
//    - Have same _asyncDbPool available for later fetch() calls if needed
//
// Result: Worker from CSV is fully functional. If static data changes during
// the day (onUpdate triggered), it can still call fetch() to refresh from DB.