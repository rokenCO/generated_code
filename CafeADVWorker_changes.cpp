/******************************************************************************
 * CafeADVWorker Changes
 * 
 * Modify the existing CafeADVWorker constructor to accept optional cached data.
 * If cached data is provided, start LIVE. Otherwise, start INITIALISING and
 * fetch from DB.
 * 
 *****************************************************************************/

// =============================================================================
// INCLUDE IN HEADER (add to includes)
// =============================================================================

#include "CafeADVCalculatorCSV.h"  // For CachedADVEntry


// =============================================================================
// MODIFY CONSTRUCTOR DECLARATION (CafeADVWorker.h)
// =============================================================================

public:
    /**************************************************************************
     * Constructor
     * 
     * @param specification     ADV specification
     * @param mds               Message delivery service  
     * @param staticDataSource  Static data source
     * @param timeManager       Time manager
     * @param asyncDbPool       Async DB pool
     * @param flog              Logger
     * @param cachedData        Optional pre-loaded data from CSV cache
     *                          - If set: start LIVE with cached data
     *                          - If not set: start INITIALISING, fetch from DB
     **************************************************************************/
    CafeADVWorker(
        const ADVSpecification&                 specification,
        MessageDeliveryService*                 mds,
        staticdata::InstrumentStaticSource*     staticDataSource,
        TimeManager*                            timeManager,
        std::shared_ptr<db::AsyncDbPool>        asyncDbPool,
        FLog                                    flog,
        std::optional<CachedADVEntry>           cachedData = std::nullopt);


// =============================================================================
// MODIFY CONSTRUCTOR IMPLEMENTATION (CafeADVWorker.cpp)
// =============================================================================

CafeADVWorker::CafeADVWorker(
    const ADVSpecification&                 specification,
    MessageDeliveryService*                 mds,
    staticdata::InstrumentStaticSource*     staticDataSource,
    TimeManager*                            timeManager,
    std::shared_ptr<db::AsyncDbPool>        asyncDbPool,
    FLog                                    flog,
    std::optional<CachedADVEntry>           cachedData)
    : MessageRecipient(mds)
    , _specification(specification)
    , _staticDataSource(staticDataSource)
    , _timeManager(timeManager)
    , _asyncDbPool(asyncDbPool)
    , _flog(flog)
{
    // ----- SAME AS BEFORE: Setup logging -----
    std::string dateTimeStr;
    std::string dateStr;
    if (!_specification._dateTime.isNull()) {
        dateTimeStr = StringStr() << _specification._dateTime << "/";
    }
    if (!_specification._date.isNull()) {
        dateStr = StringStr() << _specification._date << "/";
    }
    
    _flog = FLog(parent: flog, tag: StringStr() << "CADV/"
          << sft::format(symbol: specification._instrument)
          << "//"
          << dateStr
          << dateTimeStr);
    
    // ----- NEW: Check if we have cached data -----
    if (cachedData) {
        // Cache hit - set data immediately and go LIVE
        _data = cachedData->data;
        _date = cachedData->date;
        _asOfDate = cachedData->date;
        
        FLOG_DEBUG(_flog, StringStr() << "Using cached data, setting LIVE");
        
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
                specialDayMultiplier: cachedData->specialDayMultiplier),
            data: _data,
            errorList: ADVError(),
            condition: Condition::LIVE);
    } else {
        // Cache miss - initialize with NAN and INITIALISING (original behavior)
        _data = ADVData(
            dailyVolume: NAN,
            openingVolume: NAN,
            closingVolume: NAN,
            intradayAuctionVolume: ADVData::IntradayAuctionVolumeContainer(),
            avgTradeSize: NAN,
            avgContinuousTradeSize: NAN);
        
        FLOG_DEBUG(_flog, StringStr() << "No cached data, setting INITIALISING");
        
        set(
            description: ADVDescription(
                instrument: _specification._instrument,
                period: _dayCount,
                averageType: _specification._averageType.get(defaultValue: ADVType::MEDIAN),
                scope: _specification._scope,
                adjusted: false,
                source: "CAFEADV",
                date: _specification._date,
                dateTime: _specification._dateTime,
                realisedVolumeHistory: analysis::RealisedVolumes(),
                exceptionDates: std::vector<volt::Date>(),
                specialDayMultiplier: ADVDescription::SpecialDayMultiplierOpt()),
            data: _data,
            errorList: ADVError(),
            condition: Condition::INITIALISING);
    }
    
    // ----- SAME AS BEFORE: Register for static data updates -----
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
    
    // ----- SAME AS BEFORE: Call bing() -----
    bing();
}


// =============================================================================
// SUMMARY OF CHANGES
// =============================================================================
//
// 1. Add optional parameter: std::optional<CachedADVEntry> cachedData = std::nullopt
//
// 2. In constructor body, check if cachedData has value:
//    - YES: Set _data, _date, _asOfDate from cache, call setIfChanged with LIVE
//    - NO:  Set _data to NAN, call set with INITIALISING (original behavior)
//
// 3. Rest of constructor unchanged:
//    - Register static data listener
//    - Call bing()
//
// The optional parameter with default value means:
//    - Existing code that calls CafeADVWorker(...) without cachedData still works
//    - CafeADVCalculator passes cachedData when found in cache
//